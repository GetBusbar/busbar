// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The OK arms of B-SYNC and B-OPEN (IF §14): what core pays for one crossing through its port, set against a
//! pass mark derived in the same run from measured parts, never from a constant.
//!
//! - **The floor** is the interface itself: the same no-op call straight through busbar-ffi on a linked image,
//!   with its own answer lease (its ACTIVE registration, which `grow` needs) and nothing of the wrapper.
//! - **The kept protections**, each timed alone: the entry guard (`entry::guard` on an empty handle: the owner and
//!   entry-depth marks, the store-migration denial, the watchdog word, the arena check), the hand-over of the
//!   growable answer block (the guard with a held block, less the guard and the floor's own lease), the per-thread answer
//!   loan with its wipe of what the call wrote (`sync_out`, the adapters' loan, around nothing), and the
//!   validation of the answer
//!   (`Answer::parse`).
//! - **The margin** is the run-to-run noise, measured: the largest p90-minus-median spread of the arms timed.
//!
//! The mark is `floor + protections + margin`. Each figure is the median of `RUNS` batches of `BATCH` calls
//! after `WARM` calls (one clock read per batch, so the clock is not in the figure). The verdict is printed;
//! the timing is a recorded figure, because shared CI runners do not hold a nanosecond figure still. The hard
//! gate for the same path is C-ALLOC's heap-call count (busbar-plugin-test `tests/c_alloc.rs`).

use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

use busbar_plugin_abi::host::{Host, HostFns};
use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::host_side::entry::guard;
use busbar_plugin_abi::host_side::pool::{Pool, PooledOut, sync_out};
use busbar_plugin_abi::host_side::watch;
use busbar_plugin_abi::plugin::__rt::host::{Instance, OpenAnswer, OutLease, Session};
use busbar_plugin_abi::plugin::__rt::image::Admitted;
use busbar_plugin_abi::plugin::__rt::{Arg, kind as marker};
use busbar_plugin_abi::transport::{self as tp, ConnInfo};
use busbar_plugin_abi::types::{Bytes, Status, Str};
use busbar_plugin_test::FakeNeeds;
use busbar_plugin_test::suites::harness::Harness;
use busbar_ports::transport::{ConnIn, TransportOut, TransportPort, TransportSession};

#[path = "../../../busbar-plugin-test/tests/fixtures/min3_transport.rs"]
mod min3_transport;

const WARM: usize = 50_000;
const BATCH: usize = 20_000;
const RUNS: usize = 41;

/// The median and the p90 of `RUNS` batch averages of `f`, in nanoseconds per call.
pub fn time(mut f: impl FnMut()) -> (f64, f64) {
    for _ in 0..WARM {
        f();
    }
    let mut runs: Vec<f64> = (0..RUNS)
        .map(|_| {
            let start = Instant::now();
            for _ in 0..BATCH {
                f();
            }
            start.elapsed().as_nanos() as f64 / BATCH as f64
        })
        .collect();
    runs.sort_by(f64::total_cmp);
    (runs[RUNS / 2], runs[RUNS * 9 / 10])
}

static HOST: Host = Host::new(
    0,
    HostFns {
        now: None,
        mono: None,
        random: None,
        crypto: None,
        log: None,
        log_level: None,
        grow: None,
        deployment: None,
        migrate_admit: None,
    },
);

/// The connection every arm opens its session for (the fixture is a client framer).
pub fn conn_in() -> ConnIn<'static> {
    ConnIn {
        role: tp::ROLE_CLIENT,
        flags: 0,
        alpn: "",
        sni: "",
        peer: "192.0.2.1:50000",
        local: "192.0.2.2:8443",
        tls_peer_cert: &[],
        leftover: &[],
        head: &[],
        local_fingerprint: "",
        mono_ns: 1,
    }
}

fn conn_info() -> ConnInfo<'static> {
    ConnInfo {
        role: tp::ROLE_CLIENT,
        flags: 0,
        alpn: Str::EMPTY,
        sni: Str::EMPTY,
        peer: Str::EMPTY,
        local: Str::EMPTY,
        tls_peer_cert: Bytes::EMPTY,
        leftover: Bytes::EMPTY,
        head: Bytes::EMPTY,
        local_fingerprint: Str::EMPTY,
        mono_ns: 1,
    }
}

/// The fixture straight through busbar-ffi: no port, no adapter, no guard, no thread loan. Its answers go to a
/// 64-byte stack block lent for each call (`OutLease::with_fixed`: the ACTIVE registration `grow` needs, a wipe
/// of 64 bytes): a no-op call writes nothing and an opener writes one TOKEN record, so the block is never short.
pub struct Raw {
    inst: Arc<Instance<marker::Transport>>,
    session: Session<marker::Transport>,
}

impl Raw {
    pub fn open() -> Raw {
        let admitted =
            Admitted::linked(&min3_transport::PLUGIN).unwrap_or_else(|e| panic!("admit: {e:?}"));
        let mut lease = OutLease::new(vec![0; 4096], 1 << 20).expect("a free ACTIVE slot");
        let OpenAnswer::Done(Status::OK, Some(inst)) =
            admitted.open::<marker::Transport>(&HOST, b"{}".to_vec(), 0, &mut lease)
        else {
            panic!("the fixture's open answers OK with INSTANCE");
        };
        drop(lease);
        let inst = Arc::new(inst);
        let mut block = [0_u8; 64];
        let session = OutLease::with_fixed(&mut block, |lease| Raw::begin(&inst, lease))
            .expect("a free ACTIVE slot");
        Raw { inst, session }
    }

    /// One `begin` straight through busbar-ffi, answering on `lease`.
    pub fn begin(
        inst: &Arc<Instance<marker::Transport>>,
        lease: &mut OutLease<'_>,
    ) -> Session<marker::Transport> {
        let conn = conn_info();
        let (status, session) = inst.open_session1(|vt| &vt.begin, Arg::view(&conn), lease);
        assert_eq!(status, Status::OK, "the fixture opens a client session");
        session.expect("a session")
    }

    /// `call` with the instance, the open session and a lease of a 64-byte stack block.
    pub fn with<R>(
        &mut self,
        call: impl FnOnce(
            &Arc<Instance<marker::Transport>>,
            &mut Session<marker::Transport>,
            &mut OutLease<'_>,
        ) -> R,
    ) -> R {
        let mut block = [0_u8; 64];
        let (inst, session) = (&self.inst, &mut self.session);
        OutLease::with_fixed(&mut block, |lease| call(inst, session, lease))
            .expect("a free ACTIVE slot")
    }
}

/// The port core calls, over the same fixture, admitted by the SDK test host.
pub struct Port {
    _harness: Harness,
    pub port: Arc<dyn TransportPort>,
}

impl Port {
    pub fn open() -> Port {
        let harness = Harness::admit(min3_transport::PLUGIN.plugin(), FakeNeeds::default())
            .unwrap_or_else(|r| panic!("admit: {r:?}"));
        let port = harness
            .open_transport("b-ok", b"{}")
            .unwrap_or_else(|e| panic!("open: {e:?}"));
        Port {
            _harness: harness,
            port,
        }
    }

    /// One session through the port, as core opens it.
    pub fn begin(&self) -> TransportSession {
        self.port
            .begin(&conn_in(), &mut |_o: TransportOut<'_>| {})
            .unwrap_or_else(|e| panic!("begin: {e:?}"))
    }
}

/// The kept protections of one sync crossing, each timed alone: (name, median, p90).
pub fn protections() -> Vec<(&'static str, f64, f64)> {
    watch::init();
    let mut empty = PooledOut::default();
    let (g, gp) = time(|| {
        black_box(guard(3, 2, &mut empty, |_lease: &mut OutLease| ()));
    });
    let (l, lp) = time(|| {
        sync_out(1 << 20, |out| {
            black_box(out.capacity());
        });
    });
    let (p, pp) = time(|| {
        black_box(Answer::parse(Status::OK, black_box(&[])).is_ok());
    });
    // The hand-over of the pooled answer block (the lease that can grow): the guard with a held block, less the
    // guard alone, less the fixed lease the floor already pays.
    let mut held = Pool::global().acquire(1 << 20);
    let (gh, ghp) = time(|| {
        black_box(guard(3, 2, &mut held, |lease: &mut OutLease| lease.len()));
    });
    let mut block = [0_u8; 64];
    let (fx, _) = time(|| {
        black_box(OutLease::with_fixed(&mut block, |lease| lease.len()));
    });
    let hand_over = (gh - g - fx).max(0.0);
    vec![
        (
            "entry guard (owner, entry depth, migration denial, watchdog word, arena check)",
            g,
            gp,
        ),
        (
            "hand-over of the growable answer block",
            hand_over,
            hand_over + (ghp - gh),
        ),
        ("per-thread answer loan and its wipe", l, lp),
        ("answer validation", p, pp),
    ]
}

/// Prints the arm, its floor, the protections and the derived mark; the verdict is recorded, not enforced.
pub fn verdict(arm: &str, ok: (f64, f64), floor: (f64, f64), kept: &[(&str, f64, f64)]) {
    let spread = |(median, p90): (f64, f64)| p90 - median;
    let margin = kept
        .iter()
        .map(|&(_, m, p)| p - m)
        .chain([spread(ok), spread(floor)])
        .fold(0.0, f64::max);
    let sum: f64 = kept.iter().map(|&(_, m, _)| m).sum();
    let mark = floor.0 + sum + margin;
    println!(
        "{arm}: floor (the interface through busbar-ffi) {:.1} ns",
        floor.0
    );
    for (name, median, p90) in kept {
        println!("{arm}:   protection, {name}: {median:.1} ns (p90 {p90:.1})");
    }
    println!(
        "{arm}: OK arm median {:.1} ns (p90 {:.1}); mark {mark:.1} ns = floor {:.1} + protections {sum:.1} + \
         margin {margin:.1} (the largest measured p90-median spread); {}",
        ok.0,
        ok.1,
        floor.0,
        if ok.0 <= mark {
            "within the mark"
        } else {
            "OVER the mark"
        }
    );
    println!(
        "{arm}: not in the mark, {:.1} ns: the port's own layer (the adapter's dispatch and its two-pass decode of \
         the answer, before any item reaches the sink) and anything not named above",
        ok.0 - floor.0 - sum
    );
}
