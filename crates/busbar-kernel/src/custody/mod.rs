// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Custody: SECRET Needs, kernel secrets and the outbound-credential cache keys and policy (IF §12.2). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-K2 fills it.

use core::future::Future;

use busbar_plugin_abi::host_side::caller::Caller;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CustodyDenied {
    ForeignHandle,
    NoSuchSecretSource,
    Cycle,
    NotFound,
    Unavailable,
    Denied,
}
/// SECRET Needs (by handle) and every secret the kernel itself needs (mTLS certs, upstream keys).
/// 1. Resolve `handle` in `bindings.secret(who.instance, handle)` (§12.7). None => ForeignHandle, audited
///    `secret_handle_foreign` with the instance's kind and configured name (§12.20 attribution rule) (C-SECRET-FOREIGN).
/// 2. SecretRef::None => NotFound. Source{module, settings} => the secret instance configured as `module`;
///    Template => fill each placeholder through step 3 and render the template text; **round 17: custody keeps
///    every fill value (Zeroizing) beside the rendered value until step 5 has registered them all**.
/// 3. Cycle refusal: `cx = CallCx { stack: who.stack.push(who.instance)?, .. }` (push fails at depth 4 =>
///    Cycle); if `cx.stack.contains(target.instance())` => Cycle. Then `target.resolve(cx, settings_json)`;
///    the target's adapter copies cx.stack into its Caller, so a nested SECRET from the target arrives here
///    with the whole chain (C-SECRET-CYCLE: A -> B -> A refused at the second hop, no recursion to deadline).
/// 4. Cache per policy and F_LEASE_S, zeroize, audit the resolve. Never names the secret source in any
///    error that reaches a plugin (every variant maps to NeedErr::Denied/Absent/Unavailable with no text).
///    **Round 7 (I14): the plugin-facing cache is keyed by `(who.instance, handle)`** — the runtime instance
///    id, so the new instance after `migrate`, reconfigure or reopen starts with an empty cache. Nothing in it
///    is shared with another instance or with `resolve_ref`. Fetches from the secret plugin *may* be
///    de-duplicated underneath by a source-level cache keyed by the canonical SecretRef (shared with
///    `resolve_ref` and between instances binding the same source), but a source-level hit is still a miss of
///    the per-instance cache and goes through step 5. `CustodyKey { instance: u64, handle: u32 }` is the
///    per-instance key; `generation(who, handle)` reads that entry; unbind/close drops the instance's entries.
/// 5. **On a per-instance cache miss only** (the instance's first resolve of the handle, a lease renewal or a
///    rotation, whether or not the source-level cache hit), register the value in `who`'s instance scrub set
///    under the binding handle: `scrub.register(handle, &[&value])` (§12.16), before returning it. **Round 17
///    (I14): a Template registers the rendered value and every fill in the same call,
///    `scrub.register(handle, &[&rendered, &fill_1, .., &fill_n])`** (same lock rule, same digest compare, one
///    rebuild), so a plugin line holding only a fill (`token <fill> rejected`, a scheme stripped off `Bearer
///    <fill>`) is masked; a fill shorter than `MIN_NEEDLE` is audited `secret_too_short_to_scrub` like any value.
///    The fills come from the same resolve (origin/dev secret_ref.rs:220-252 `resolve_template_typed` order), never
///    from a second one. **Round 19 (I14), normative: register, then publish.** A miss runs in exactly this
///    order: resolve (step 3); `scrub.register(..)` **returns** (its `ArcSwap::swap` is done); the value is
///    published in the per-instance cache entry (a `Release` store, read by the hit path with `Acquire`);
///    `generation` is bumped; the value is returned. So no consumer of the per-instance cache (a SECRET Need, the
///    connector's `CertDigests`, a kernel-slot user) can obtain a value before the instance's scrub snapshot
///    masks it, and a FAIL or log line built from it is scrubbed by a snapshot that holds it. Misses of one
///    `CustodyKey` are **single-flight**: the entry holds one in-flight resolve per value generation
///    (`tokio::sync::OnceCell::get_or_try_init` semantics; a lease renewal or rotation installs a fresh cell under
///    the shard lock, compare-and-replace on the expired cell only); every other caller that misses on that key
///    awaits it and returns the published value without registering; if the leading future is dropped (chain
///    cancel) or fails, one waiter becomes the leader, and a failure is never cached. An expired value is never
///    served while its renewal is in flight. Publishing first and registering after is forbidden (it opens a window
///    in which a hit returns a value no snapshot masks, §16.155). A per-instance cache hit does nothing but an
///    `Acquire` load and a clone of the published Arc: no lock, no allocation, no registration — and that
///    instance's scrub snapshot already masks that value, because its publish happened after the swap. The
///    kernel's own slots (`slot >= 0x1_0000`, §12.16) follow the same order. A value whose SHA-256 equals what that
///    handle already holds is a no-op in `register`; a new value **replaces** the handle's current value, and
///    **round 18 (I14): the value it replaces stays registered as that handle's previous generation**, masked until
///    the handle changes again or the instance closes (`Scrub::register` shifts, §12.16): a chain that resolved v1
///    before a renewal and fails after it, or v1 kept in instance state since `open` (connection credentials, an
///    outbound key), still has v1 masked. The generation before that is dropped (zeroized); never more than two. `resolve_ref` registers in no instance's set
///    (it has no instance; kernel-internal secrets for an instance use the kernel slots, §12.16).
/// Not dyn: `resolve` is RPITIT (I5: no SECRET step boxes); HostNeeds and every other consumer is generic over
/// `C: SecretCustody`. A cache hit returns a clone of the cached Arc (no allocation). `generation(who, handle)`
/// changes whenever step 5 stores a new value for that handle; the connector's `CertDigests` cache (§13) compares
/// it to know when to re-hash a client cert, so OPEN never resolves a cert just to build its PoolKey.
pub trait SecretCustody: Send + Sync + 'static {
    // W0-ABI: the IF's value type is `zeroize::Zeroizing<Vec<u8>>`, which core bans (clippy-crate-wide
    // disallowed-types, LR-094); the stub uses its replacement `busbar_contract::secure::SecureVec`.
    fn resolve(
        &self,
        who: &Caller<'_>,
        handle: u32,
    ) -> impl Future<
        Output = Result<std::sync::Arc<busbar_contract::secure::SecureVec>, CustodyDenied>,
    > + Send;
    /// One Relaxed load: the value generation of (who.instance, handle), 0 = never resolved.
    fn generation(&self, who: &Caller<'_>, handle: u32) -> u64;
    // W0-ABI: `resolve_ref(&'a self, cx: CallCx, r: &'a SecretRef) -> BoxFut<'a, Result<Zeroizing<Vec<u8>>,
    // CustodyDenied>>` (doc: "Kernel-internal callers (no plugin caller): by SecretRef directly, with an empty
    // stack.") names `CallCx`, a busbar-plugin-loader type (IF §11.3); the kernel does not depend on the
    // loader in wave 0. W1-K2 adds it with that dependency.
}
/// Outbound credentials from auth plugins (F_CACHE_S > 0). Core-owned custody. The key separates every input
/// that changes the credential: a down-scoped token (RFC 8693, one per scope) never serves another scope, and a
/// caller-grant credential never serves another caller.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct CredKey {
    pub auth_instance: u64,
    pub upstream: u64,
    pub scope: [u8; 32], /* SHA-256 of O_SCOPE, zero = none or a binding without STYLE_SCOPE */
    pub caller: [u8; 32], /* SHA-256 of ID_SUBJECT for a caller-mode binding (STYLE_CALLER), zero = none */
}
/// Round 23 (185, 235): the outbound-mint decisions auth-oauth made for itself (single-flight cells and parked
/// tickets, refresh skew, the mint-rate floor, the post-failure window, the scope-cell cap, the mint deadline)
/// are core's, here, and nowhere else. Config `auth.outbound.*`, core vocabulary, read once at load (K2 parses it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredPolicy {
    /// Refresh-ahead margin (`refresh_ahead_s`, default 300 = today's REFRESH_SKEW_SECS, 0..=3600). Sent to the
    /// plugin as FACT(F_MIN_VALID_S) on every outbound call (§8.3).
    pub refresh_ahead_s: u32,
    /// Least time between two mint starts for one key (`min_mint_interval_s`, default 5, 1..=60).
    pub min_mint_interval_s: u32,
    /// The mint call's own deadline (`mint_deadline_s`, default 30, 1..=120), independent of any one request.
    pub mint_deadline_s: u32,
    /// Most keys one auth instance holds (`max_keys_per_instance`, default 256 = today's MAX_SCOPE_CELLS).
    pub max_keys_per_instance: u32,
    /// Round 24: the longest core holds one minted value, whatever lifetime its issuer stated (`max_hold_s`,
    /// default 86,400 = today's MAX_REFRESH_SECS, auth-oauth mint/mod.rs:46-48, applied at :278; 60..=604,800),
    /// so a revoked token is not presented for the process's life.
    pub max_hold_s: u32,
}
// W0-ABI: `CredGet<'a>` (Ready/Wait/Direct over `OutboundAnswer` and `PortError`) and the `CredentialCache` trait
// (`get`, `evict_instance`, `evict_caller`; rules 1-7) name busbar-plugin-loader types (IF §11.3); the kernel does
// not depend on the loader in wave 0. W1-K2 adds both, with their IF doc lines, with that dependency.
