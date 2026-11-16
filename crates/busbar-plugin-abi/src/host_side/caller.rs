// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host-side caller identity, instance limits and the transport-security verdict (IF §10.3, §48; W1-H1).

use core::cell::Cell;
use core::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::types::KindCode;

pub type BoxFut<'a, T> = core::pin::Pin<Box<dyn core::future::Future<Output = T> + Send + 'a>>;

/// The instance ids of the host call stack, innermost last. Max depth 4. Copy, carried across ports in
/// `CallCx::stack` (§11.3) so custody sees the whole chain A -> custody -> B -> custody -> A.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallStack {
    pub ids: [u64; 4],
    pub depth: u8,
}
impl CallStack {
    /// Whether `instance` is on the stack. Only the first `depth` ids count (a `depth` past 4 reads as 4).
    pub fn contains(&self, instance: u64) -> bool {
        let depth = usize::from(self.depth).min(self.ids.len());
        self.ids.iter().take(depth).any(|&id| id == instance)
    }
    /// None when depth is already 4 (custody then refuses: CustodyDenied::Cycle).
    pub fn push(self, instance: u64) -> Option<CallStack> {
        let mut next = self;
        let slot = next.ids.get_mut(usize::from(self.depth))?;
        *slot = instance;
        next.depth = self.depth.checked_add(1)?;
        Some(next)
    }
}

/// Who is asking, as core knows it. Never shown to any plugin.
/// **Round 14: `Caller<'a>` borrows, so building one does no refcount RMW.** `plugin` and `name` are `&'a str`
/// borrowed from the long-lived owner: for an instance chain, from the `&'a Instance` the async proxy already
/// borrows through `&'a Proxy` (`&inst.identity`, `&inst.name`); for an Image-owned chain (open, migrate), from
/// the registry's admitted-image entry and the `InstanceSpec` the open/migrate future borrows; for a store-lane
/// job, from the `Arc` of proxy state the job owns (I5's stated lane pair). Every other field is Copy, so the
/// adapter builds a `Caller` per call with plain stores and the `ChainGuard` borrows it (§10.5). A consumer that
/// keeps a caller's identity past the call (a queued push, a carrier owner) copies the text into its own cold
/// storage; nothing on a chain clones an `Arc<str>`. Everywhere this file writes `&Caller` or `&'a Caller` in a
/// signature (§10.3 `Needs`, §12), read `&Caller<'_>` / `&'a Caller<'_>`: the elided lifetime is the frozen form.
#[derive(Clone, Copy, Debug)]
pub struct Caller<'a> {
    /// The verified stamp name (r4 §3.3). The record namespace, custody, quota, audit and the egress profile key off it.
    pub plugin: &'a str,
    pub kind: KindCode,
    /// The operator's configured instance name (`InstanceSpec.name`): stable across restart, reconfigure and
    /// replicas. Everything core keeps durably on a plugin's behalf is keyed by (plugin, name): records (§12.5),
    /// caller connections (§12.12), tickets (§12.11), login state (§12.6), queued pushes (§12.9), the trust
    /// book (§12.14). Never a runtime id and never a config hash.
    pub name: &'a str,
    /// Runtime only (in-memory tables: bindings, pools, caches, watchdog). Allocated by the registry before
    /// `describe`/`open` run, so open chains have it too. Never persisted.
    pub instance: u64,
    /// The instance's watchdog slot (§10.6).
    pub slot: u32,
    /// **Round 15: the host-side chain identity.** Unique for every chain the process ever runs and never reused
    /// (no two chains of any instance, live or past, share a value), and never 0. Written only by
    /// `Driver::new` (§10.5), which overwrites whatever the adapter put here with `next_chain()` below; a
    /// sync call has no `Driver` and carries 0, and no Needs method is ever called with 0 (the connector refuses
    /// one as `NeedErr::Invalid`, C-CONN-SCOPE). It is not the chain token (a token is plugin-side, minted only at
    /// the first NEED, and collides across instances because every instance's slots start at index 0,
    /// generation 1, §6.5); nothing ever derives one from the other. The connector's conn table is keyed by
    /// `(instance, chain, conn id)` (§13), so `release` closes only this chain's conns and a conn id presented
    /// under another chain is INVALID (§6.1).
    pub chain: u64,
    pub deadline: Instant,
    /// The stack *outside* this call (from CallCx). The driver never pushes; custody pushes `instance`
    /// before it calls a SecretPort (§12.2).
    pub stack: CallStack,
    pub out_of_process: bool,
    /// Round 8: the instance's core-owned operator limits (§12.22), copied from the Instance (Copy, 16 bytes; no
    /// allocation). The connector applies `connect_timeout_ms`/`timeout_ms` to dials and I/O and
    /// `plaintext` to TLS_NONE/`http://` Needs; `deadline` above already includes `timeout_ms`.
    pub limits: InstanceLimits,
}

/// Round 15: mint a host-side chain id (`Caller::chain`). `(ord << 32) | n`: `ord` is this thread's ordinal, taken
/// once per thread lifetime with one `fetch_add(1, Relaxed)` on a process-global `AtomicU64` that starts at 1 and
/// is never decremented (so ordinals are never reused, even after the thread exits, and the id is never 0); `n`
/// is a plain thread-local `Cell<u32>` counter (load, add, store: no RMW, no lock, no clock). When `n` would wrap,
/// the thread takes a fresh ordinal (one more `fetch_add`, once per 2^32 chains on that thread). The id is
/// minted on the thread that builds the `Driver`; the future may then move to any worker without changing it.
/// The per-thread `fetch_add` is I5's third stated once-per-thread exception (like watchdog registration, §10.6);
/// C-RMW counts it once per thread, never per chain. Ordinals overflow only after 2^32 thread births plus
/// counter wraps, which no process reaches; debug builds assert it.
pub fn next_chain() -> u64 {
    let mut ord = ORDINAL.get();
    let mut n = COUNTER.get();
    if ord == 0 || n == u32::MAX {
        ord = ORDINALS.fetch_add(1, Ordering::Relaxed);
        debug_assert!(ord < 1 << 32, "chain-id thread ordinals exhausted");
        ORDINAL.set(ord);
        n = 0;
    }
    COUNTER.set(n + 1);
    (ord << 32) | u64::from(n)
}

/// The next thread ordinal; starts at 1 and is never decremented, so no chain id is 0 or reused.
static ORDINALS: AtomicU64 = AtomicU64::new(1);

std::thread_local! {
    /// This thread's ordinal (0 = none taken yet).
    static ORDINAL: Cell<u64> = const { Cell::new(0) };
    /// The low 32 bits of this thread's next chain id.
    static COUNTER: Cell<u32> = const { Cell::new(0) };
}

/// Round 8 (§12.22): core-owned per-instance limits. There is no `limits` config key: 0 = the kind default, and the
/// plugin's settled LIMITS answer is applied in memory at its open.
/// Never part of the bag a plugin sees. 0 = unset (kind default) in every numeric field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
/// Round 32: `plaintext: Plaintext` is replaced by `accept`, the instance's parsed `insecure_transport.accept`
/// (TRANSPORT-SECURITY-POLICY §4; K7 parses and strips it like `limits`); `Plaintext` and `limits.plaintext` are gone.
pub struct InstanceLimits {
    pub timeout_ms: u32,
    pub connect_timeout_ms: u32,
    pub max_inflight: u32,
    pub accept: Accept,
}

/// Round 32: a two-bit set; empty (the default) = verified TLS only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Accept(pub u8);
impl Accept {
    pub const PLAINTEXT: u8 = 1;
    pub const UNVERIFIED_TLS: u8 = 2;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Verify,
    WaiveVerify,
    Plain,
    Refuse,
}

/// Round 32 (TRANSPORT-SECURITY-POLICY §3): the one transport-security decision, called by the connector's
/// OPEN/STARTTLS/FETCH handlers (C1, before the pool lookup and DNS) and by the registry over a `check`'s
/// ENDPOINTs (L2) and K7 over a transport instance's core-known client endpoints. No kind, module or loopback
/// parameter, no DNS, no allocation. TLS_* → Verify (WaiveVerify only under UNVERIFIED_TLS); TLS_NONE, `unix:`
/// and `http://` → Plain only under PLAINTEXT, else Refuse. It lives here (host side, H1) and not in the connector
/// because busbar-kernel names nothing in busbar-core-connector (its Cargo.toml) and both callers reach this crate.
pub fn transport_verdict(accept: Accept, tls: u32, dest: &str) -> Verdict {
    use crate::need::need_flag::{TLS_INBAND, TLS_MASK, TLS_NONE};
    let mode = tls & TLS_MASK;
    if mode > TLS_INBAND {
        return Verdict::Refuse;
    }
    let names = |prefix: &str| {
        dest.get(..prefix.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
    };
    // The dest's own form decides first: a unix socket carries no TLS, and a FETCH URL's scheme is its mode.
    let secured = if names("unix:") || names("http://") {
        false
    } else {
        names("https://") || mode != TLS_NONE
    };
    match (secured, accept.0) {
        (true, a) if a & Accept::UNVERIFIED_TLS != 0 => Verdict::WaiveVerify,
        (true, _) => Verdict::Verify,
        (false, a) if a & Accept::PLAINTEXT != 0 => Verdict::Plain,
        (false, _) => Verdict::Refuse,
    }
}

#[cfg(test)]
mod tests {
    use super::{Accept, Verdict, transport_verdict};
    use crate::need::need_flag::{TLS_INBAND, TLS_MASK, TLS_MUTUAL, TLS_NONE, TLS_REQUIRED};

    const VERIFIED_ONLY: Accept = Accept(0);
    const PLAINTEXT: Accept = Accept(Accept::PLAINTEXT);
    const UNVERIFIED: Accept = Accept(Accept::UNVERIFIED_TLS);
    const BOTH: Accept = Accept(Accept::PLAINTEXT | Accept::UNVERIFIED_TLS);

    /// TRANSPORT-SECURITY-POLICY §3 and §4: a TLS mode is verified unless the instance accepted
    /// `unverified_tls`; TLS_NONE is refused unless it accepted `plaintext`; each accept bit admits
    /// exactly what it names and neither implies the other.
    #[test]
    fn transport_verdict_truth_table() {
        let dest = "db.internal:5432";
        for tls in [TLS_REQUIRED, TLS_MUTUAL, TLS_INBAND] {
            assert_eq!(
                transport_verdict(VERIFIED_ONLY, tls, dest),
                Verdict::Verify,
                "{tls}"
            );
            assert_eq!(
                transport_verdict(PLAINTEXT, tls, dest),
                Verdict::Verify,
                "{tls}"
            );
            assert_eq!(
                transport_verdict(UNVERIFIED, tls, dest),
                Verdict::WaiveVerify,
                "{tls}"
            );
            assert_eq!(
                transport_verdict(BOTH, tls, dest),
                Verdict::WaiveVerify,
                "{tls}"
            );
        }
        assert_eq!(
            transport_verdict(VERIFIED_ONLY, TLS_NONE, dest),
            Verdict::Refuse
        );
        assert_eq!(
            transport_verdict(UNVERIFIED, TLS_NONE, dest),
            Verdict::Refuse
        );
        assert_eq!(transport_verdict(PLAINTEXT, TLS_NONE, dest), Verdict::Plain);
        assert_eq!(transport_verdict(BOTH, TLS_NONE, dest), Verdict::Plain);
    }

    /// Policy §0 and §2: no loopback, `localhost` or unix-socket exemption. A unix socket carries no
    /// TLS, so a TLS mode on a `unix:` dest is still plaintext.
    #[test]
    fn transport_verdict_has_no_loopback_or_unix_exemption() {
        for dest in [
            "127.0.0.1:5432",
            "[::1]:5432",
            "localhost:6379",
            "unix:/run/postgresql/.s.PGSQL.5432",
        ] {
            assert_eq!(
                transport_verdict(VERIFIED_ONLY, TLS_NONE, dest),
                Verdict::Refuse,
                "{dest}"
            );
            assert_eq!(
                transport_verdict(UNVERIFIED, TLS_NONE, dest),
                Verdict::Refuse,
                "{dest}"
            );
            assert_eq!(
                transport_verdict(PLAINTEXT, TLS_NONE, dest),
                Verdict::Plain,
                "{dest}"
            );
        }
        let unix = "unix:/run/valkey.sock";
        assert_eq!(
            transport_verdict(VERIFIED_ONLY, TLS_REQUIRED, unix),
            Verdict::Refuse
        );
        assert_eq!(
            transport_verdict(UNVERIFIED, TLS_REQUIRED, unix),
            Verdict::Refuse
        );
        assert_eq!(
            transport_verdict(PLAINTEXT, TLS_REQUIRED, unix),
            Verdict::Plain
        );
    }

    /// Policy §2: a FETCH URL is judged by its scheme (`https://` = TLS, `http://` = none), whatever
    /// the mode bits say, in any letter case.
    #[test]
    fn transport_verdict_judges_a_fetch_url_by_its_scheme() {
        for url in [
            "http://vault.internal:8200/v1/x",
            "HTTP://127.0.0.1:4318/v1/traces",
        ] {
            for tls in [TLS_NONE, TLS_REQUIRED] {
                assert_eq!(
                    transport_verdict(VERIFIED_ONLY, tls, url),
                    Verdict::Refuse,
                    "{url}"
                );
                assert_eq!(
                    transport_verdict(UNVERIFIED, tls, url),
                    Verdict::Refuse,
                    "{url}"
                );
                assert_eq!(
                    transport_verdict(PLAINTEXT, tls, url),
                    Verdict::Plain,
                    "{url}"
                );
            }
        }
        for url in [
            "https://vault.internal:8200/v1/x",
            "HTTPS://collector:4318/",
        ] {
            for tls in [TLS_NONE, TLS_REQUIRED] {
                assert_eq!(
                    transport_verdict(VERIFIED_ONLY, tls, url),
                    Verdict::Verify,
                    "{url}"
                );
                assert_eq!(
                    transport_verdict(PLAINTEXT, tls, url),
                    Verdict::Verify,
                    "{url}"
                );
                assert_eq!(
                    transport_verdict(UNVERIFIED, tls, url),
                    Verdict::WaiveVerify,
                    "{url}"
                );
            }
        }
    }

    /// Fail closed: a TLS mode the interface does not define is refused under any acceptance; bits
    /// above the mode nibble (the egress class in 16..=19) do not change the mode.
    #[test]
    fn transport_verdict_refuses_an_undefined_tls_mode() {
        for tls in TLS_INBAND + 1..=TLS_MASK {
            for dest in ["db.internal:5432", "https://h/", "unix:/s"] {
                assert_eq!(
                    transport_verdict(BOTH, tls, dest),
                    Verdict::Refuse,
                    "{tls} {dest}"
                );
            }
        }
        let egress = 2 << 16;
        assert_eq!(
            transport_verdict(VERIFIED_ONLY, TLS_REQUIRED | egress, "h:1"),
            Verdict::Verify
        );
        assert_eq!(
            transport_verdict(VERIFIED_ONLY, TLS_NONE | egress, "h:1"),
            Verdict::Refuse
        );
    }
}

#[cfg(test)]
mod stack_tests {
    use super::*;

    #[test]
    fn a_stack_holds_four_ids_and_refuses_a_fifth() {
        let mut stack = CallStack::default();
        assert!(
            !stack.contains(0),
            "an empty stack holds nothing, not even id 0"
        );
        for id in 1..=4 {
            stack = stack.push(id).expect("room for four");
            assert!(stack.contains(id));
        }
        assert_eq!(stack.depth, 4);
        assert_eq!(stack.ids, [1, 2, 3, 4]);
        assert!(stack.push(5).is_none(), "depth 4 is full");
        assert!(!stack.contains(5));
    }

    #[test]
    fn contains_reads_only_the_live_depth() {
        let stack = CallStack {
            ids: [7, 8, 9, 10],
            depth: 2,
        };
        assert!(stack.contains(7) && stack.contains(8));
        assert!(
            !stack.contains(9) && !stack.contains(10),
            "ids past depth are dead"
        );
        let corrupt = CallStack {
            ids: [1, 2, 3, 4],
            depth: 200,
        };
        assert!(corrupt.contains(4), "a depth past 4 reads as 4");
        assert!(corrupt.push(5).is_none());
    }

    #[test]
    fn chain_ids_are_never_zero_and_never_repeat_on_a_thread() {
        let first = next_chain();
        let second = next_chain();
        assert_ne!(first, 0);
        assert_ne!(first, second);
        assert_eq!(first >> 32, second >> 32, "one ordinal per thread");
        assert_eq!(second, first + 1);
    }

    #[test]
    fn chain_ids_never_collide_across_threads() {
        let ids: Vec<Vec<u64>> = (0..8)
            .map(|_| std::thread::spawn(|| (0..1_000).map(|_| next_chain()).collect::<Vec<_>>()))
            .map(|t| t.join().expect("thread"))
            .collect();
        let mut all: Vec<u64> = ids.into_iter().flatten().collect();
        let n = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), n, "every chain id is unique");
        assert!(
            all.iter().all(|&id| id >> 32 != 0),
            "every id carries a non-zero ordinal"
        );
    }

    #[test]
    fn a_wrapping_counter_takes_a_fresh_ordinal() {
        let before = next_chain();
        COUNTER.set(u32::MAX - 1);
        let last = next_chain();
        assert_eq!(last, ((before >> 32) << 32) | u64::from(u32::MAX - 1));
        let wrapped = next_chain();
        assert_ne!(wrapped >> 32, before >> 32, "a fresh ordinal");
        assert_eq!(wrapped & 0xFFFF_FFFF, 0);
    }
}
