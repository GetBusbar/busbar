// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! L1 (MONEY-DESIGN §4, PR-B2): THE REQUEST PATH'S MONEY STEPS, timed. Each iteration is one
//! unit's admission (`try_admit`), its settlement (`record_usage`) and a refund (`refund_charge`) on
//! a capped key, from several threads at once, with the recorder behind it:
//!
//! - `memory`: an in-memory store;
//! - `slow-store`: a store that delays EVERY call by 1 s;
//! - `slow-disk`: a data directory whose `fsync` takes 50 ms.
//!
//! Prints p50 and p99 per iteration (median of 5 runs). The base build runs the same steps with
//! no recorder (the lines between the `RECORDER` markers removed), so the two print comparable
//! figures. Run: `cargo bench -p busbar-kernel --bench money_hot_path`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_contract::records::{RecordStore, VirtualKey};
use busbar_kernel::cost::CostModel;
use busbar_kernel::governance::{GovState, MemoryStore};

const THREADS: usize = 4;
const PER_THREAD: usize = 50_000;
const RUNS: usize = 5;

fn cost() -> CostModel {
    use busbar_kernel::config::groups::{LimitCfg, LimitMetric, LimitWindow};
    let card = BTreeMap::from([(
        "m".to_string(),
        busbar_kernel::config::RateEntryCfg {
            input_utok: 1.0,
            ..Default::default()
        },
    )]);
    let groups = BTreeMap::from([(
        "team".to_string(),
        busbar_kernel::config::GroupCfg {
            enabled: true,
            limits: vec![LimitCfg {
                metric: LimitMetric::Budget,
                amount: u64::MAX / 4,
                per: Some(LimitWindow::Day),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
                admission: None,
                on_exhaustion: None,
            }],
            ..Default::default()
        },
    )]);
    CostModel::resolve_parts(Some(&card), 0, &groups)
}

// RECORDER {
struct Slow {
    inner: busbar_kernel::posting::recorder::RecordsOnly,
    delay: Duration,
}

impl busbar_kernel::posting::recorder::PostStore for Slow {
    fn add_usage_batch<'a>(
        &'a self,
        op: busbar_kernel::posting::record::Op,
        cells: &'a [(String, u64, busbar_contract::records::UsageDelta)],
    ) -> busbar_contract::store_calls::StoreCall<'a, ()> {
        Box::pin(async move {
            tokio::time::sleep(self.delay).await;
            self.inner.add_usage_batch(op, cells).await
        })
    }
    fn add_metering_batch<'a>(
        &'a self,
        op: busbar_kernel::posting::record::Op,
        rows: &'a [busbar_contract::records::MeteringDelta],
    ) -> busbar_contract::store_calls::StoreCall<'a, ()> {
        Box::pin(async move {
            tokio::time::sleep(self.delay).await;
            self.inner.add_metering_batch(op, rows).await
        })
    }
    fn heartbeat(&self) -> busbar_contract::store_calls::StoreCall<'_, ()> {
        Box::pin(async move {
            tokio::time::sleep(self.delay).await;
            Ok(())
        })
    }
    fn get_usage<'a>(
        &'a self,
        bucket: &'a str,
        window: u64,
    ) -> busbar_contract::store_calls::StoreCall<'a, busbar_contract::records::UsageLedger> {
        self.inner.get_usage(bucket, window)
    }
}

struct SlowDisk;

impl busbar_kernel::posting::spool::Syncer for SlowDisk {
    fn sync(&self, file: &std::fs::File) -> std::io::Result<()> {
        std::thread::sleep(Duration::from_millis(50));
        file.sync_data()
    }
}
// } RECORDER

fn run(case: &str, rt: &tokio::runtime::Runtime) -> (u128, u128) {
    let store: Arc<dyn RecordStore> = Arc::new(MemoryStore::new());
    let key = VirtualKey {
        id: "vk_bench".to_string(),
        generation_hash: "hash-bench".to_string(),
        name: "bench".to_string(),
        enabled: true,
        group: Some("team".to_string()),
        ..Default::default()
    };
    store.put_key(&key).unwrap();
    let gov = Arc::new(GovState::new(Arc::clone(&store), None).unwrap());
    let _ = (case, rt);
    // RECORDER {
    let dir = std::env::temp_dir().join(format!("busbar-l1-{}-{}", case, std::process::id()));
    let (delay, medium, syncer): (_, _, Arc<dyn busbar_kernel::posting::spool::Syncer>) = match case
    {
        "slow-store" => (
            Duration::from_secs(1),
            busbar_kernel::posting::recorder::Medium::Memory,
            Arc::new(busbar_kernel::posting::spool::DataSync),
        ),
        "slow-disk" => (
            Duration::ZERO,
            busbar_kernel::posting::recorder::Medium::Dir(dir.clone()),
            Arc::new(SlowDisk),
        ),
        _ => (
            Duration::ZERO,
            busbar_kernel::posting::recorder::Medium::Memory,
            Arc::new(busbar_kernel::posting::spool::DataSync),
        ),
    };
    let post = Arc::new(Slow {
        inner: busbar_kernel::posting::recorder::RecordsOnly(Arc::clone(&store)),
        delay,
    });
    let (rec, _) = busbar_kernel::posting::recorder::Recorder::open(
        gov.ledger(),
        post,
        &medium,
        false,
        Duration::from_millis(100),
        syncer,
    )
    .unwrap();
    {
        let _g = rt.enter();
        rec.spawn();
    }
    gov.attach_recorder(Arc::clone(&rec));
    // } RECORDER
    let c = Arc::new(cost());
    let mut threads = Vec::new();
    for _ in 0..THREADS {
        let (gov, key, c) = (Arc::clone(&gov), key.clone(), Arc::clone(&c));
        threads.push(std::thread::spawn(move || {
            let units = BTreeMap::from([("input".to_string(), 100u64)]);
            let now = busbar_kernel::store::now();
            let mut times = Vec::with_capacity(PER_THREAD);
            for i in 0..PER_THREAD {
                let t = Instant::now();
                let grant = gov.try_admit(&c, &key, "", now).expect("admits");
                gov.record_usage(&c, &key, "", "m", &units, now);
                if i % 10 == 0 {
                    gov.refund_charge(grant.charge());
                }
                drop(grant);
                times.push(t.elapsed().as_nanos());
            }
            times
        }));
    }
    let mut all: Vec<u128> = threads
        .into_iter()
        .flat_map(|t| t.join().unwrap())
        .collect();
    all.sort_unstable();
    let p = |q: f64| all[((all.len() as f64 - 1.0) * q) as usize];
    // RECORDER {
    rt.block_on(async { rec.stop().await });
    let _ = std::fs::remove_dir_all(&dir);
    // } RECORDER
    (p(0.50), p(0.99))
}

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    for case in ["memory", "slow-store", "slow-disk"] {
        let mut p50s = Vec::new();
        let mut p99s = Vec::new();
        for _ in 0..RUNS {
            let (p50, p99) = run(case, &rt);
            p50s.push(p50);
            p99s.push(p99);
        }
        p50s.sort_unstable();
        p99s.sort_unstable();
        println!(
            "L1 {case:<10} p50 {:>6} ns   p99 {:>7} ns   (median of {RUNS} runs, {} units each)",
            p50s[RUNS / 2],
            p99s[RUNS / 2],
            THREADS * PER_THREAD
        );
    }
}
