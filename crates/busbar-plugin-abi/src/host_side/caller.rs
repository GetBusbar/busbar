// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host-side caller identity, instance limits and the transport-security verdict (IF §10.3, §48). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-H1 fills it.

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
    pub fn contains(&self, instance: u64) -> bool {
        let _ = instance;
        todo!()
    }
    /// None when depth is already 4 (custody then refuses: CustodyDenied::Cycle).
    pub fn push(self, instance: u64) -> Option<CallStack> {
        let _ = instance;
        todo!()
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
    todo!()
}

/// Round 8 (§12.22): core-owned per-instance limits, operator config `<kind>.<name>.limits` beside `module`.
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
    // W0-ABI stub: answers `Verify` (today's behaviour) so existing paths stay green until W1-H1 lands the rule.
    let _ = (accept, tls, dest);
    Verdict::Verify
}
