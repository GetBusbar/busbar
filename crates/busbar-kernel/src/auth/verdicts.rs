// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The verdict cache: core's one per-instance verify cache with single-flight leads (IF §12.28). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-K2 fills it.

use core::marker::PhantomData;

/// The credential a verify read, by hash only (the credential itself is never stored). `credential` = SHA-256
/// (through the facade) over, for each of the instance's D_CRED_HEADER names in declared order, the u32 LE name
/// length, the name, the u32 LE count of that header's values on the request and each value with its u32 LE length.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct VerdictKey {
    pub auth_instance: u64,
    // W0-ABI: the frozen `pub credential: [u8; 32]` (the SHA-256 above) trips the source rule
    // `a_secret_named_field_is_never_a_bare_string` (a `credential` field in a `*Key` struct must be `Secret<..>`
    // or wiped by a `Drop`, which a `Copy` key cannot have); W1-K2 lands it with the lead designer's ruling.
}
/// Config `auth.verdict_cache.*`, core vocabulary: `default_ttl_s` (300 = auth-oidc's DEFAULT_TTL_SECS; replaces
/// VerifyBook's DEFAULT_TTL_MS), `max_ttl_s` (3600 = MAX_TTL_SECS, 1..=86_400), `max_entries` per auth instance
/// (4096 = VerifyBook's MAX_KEYS and auth-oidc's MAX_ENTRIES, 0 = off), `max_identity_bytes` (8192 =
/// MAX_PRINCIPAL_BYTES; a bigger identity is verified afresh every time; replaces VerifyBook's MAX_ENTRY).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerdictPolicy {
    pub default_ttl_s: u32,
    pub max_ttl_s: u32,
    pub max_entries: u32,
    pub max_identity_bytes: u32,
}
// W0-ABI: `VerdictGet<'a>` (Hit(Identity), Lead(VerdictLead<'a>), Follow(BoxFut<.., Result<Result<Verdict,
// PortError>, VerdictLead<'a>>>), Bypass) names `Identity`, `Verdict` and `PortError`, busbar-plugin-loader types
// (IF §11.3); the kernel does not depend on the loader in wave 0. W1-K2 adds it, with its IF doc lines, with that
// dependency.
/// One standing lead (VerifyBook's `lead_until`). Holds the cache, the key and the instance's flush epoch read in
/// `begin` (rule 6).
pub struct VerdictLead<'a> {
    // W0-ABI: private fields (&'a cache, key: VerdictKey, epoch: u64) land with W1-K2.
    _stub: PhantomData<&'a ()>,
}
// W0-ABI: `VerdictLead::settle(self, outcome: &Result<Verdict, PortError>, now_s: u64)` names loader types (see
// above), and `impl Drop for VerdictLead<'_>` (the lead passes to the first follower on drop) is not stubbed (a
// `todo!()` drop would panic); W1-K2 adds both with their IF doc lines.
/// Rules, normative:
/// 1. **Eligible instances**: an instance whose image declares ≥ 1 D_CRED_HEADER and neither FB_NEEDS_BODY nor
///    FB_NEEDS_BODY_HASH (a body-bound or per-request signature is never a reusable credential). Others get
///    `Bypass` with no lock taken.
/// 2. **Eligible answers**: only `Verdict::Identity` from `verify`/`verify_io` with no REPLAY, not reached through
///    ISSUED_WANTED (an issued credential's revocation is immediate, §12.8), with `F_CACHE_S` ≠ 0 (0 = never) and
///    `identity_records().len()` ≤ `max_identity_bytes`. NotMine, Rejected, KEYS_STALE and every `PortError`
///    are never cached (they are shared with the lead's followers only, rule 4).
/// 3. **TTL** = min(F_CACHE_S if stated else `default_ttl_s`, F_EXPIRES_AT_S − now_s if stated (≤ 0: not
///    cached), `max_ttl_s`). The plugin states facts (its token's expiry, a suggested lifetime); core picks the TTL.
/// 4. **Lookup and single-flight** (K8, before `AuthPort::verify` for each eligible instance in the route's
///    effective chain, in chain order): `begin` answers `Hit` for a fresh entry (read lock only); otherwise, under
///    the shard's write lock, `Follow` if a lead stands for the key (now < `lead_until`), else `Lead` with
///    `lead_until` = now + `LEAD_MS`. So a burst of N requests carrying the same cold credential makes one plugin
///    verify and, for `verify_io`, one set of upstream Needs (JWKS, LDAP bind, GitHub user lookup), not N; the
///    other N − 1 return the leader's outcome. Round 23's "no single-flight" is withdrawn: under I1 a plugin has
///    no I/O of its own, so a duplicate miss is a duplicate core-run upstream call, and VerifyBook already
///    collapses them. A lead that lapses (`LEAD_MS`, a hung leader past its own deadline) passes to the first
///    follower by the kept `expire` sweep, which K2 runs on the watchdog tick.
/// 5. **Capacity** (VerifyBook's `room`, kept): at `max_entries` keys for an instance, a new key first drops that
///    instance's idle expired entries, then its idle entry with the soonest expiry; if every entry is leading or
///    followed, `begin` answers `Bypass`. Round 23's oldest-inserted rule (auth-oidc's) is replaced by core's.
/// 6. **Flush**: every entry of an instance is dropped when its `refresh` completes OK (scheduled or after
///    KEYS_STALE), when a verify answers KEYS_STALE, on reconfigure (a new instance id starts empty) and on close.
///    Each instance has a flush epoch (one Relaxed counter); a lead carries the epoch read in `begin`, and its
///    fill is discarded if the epoch moved, so a verdict reached before a flush never outlives it (its followers
///    still get the outcome: they asked before the flush, like the leader). A flush keeps standing leads.
pub trait VerdictCache: Send + Sync + 'static {
    // W0-ABI: `begin<'a>(&'a self, key: VerdictKey, now_s: u64) -> VerdictGet<'a>` returns `VerdictGet` (see above);
    // W1-K2 adds it once the kernel depends on plugin-loader.
    fn epoch(&self, auth_instance: u64) -> u64;
    fn flush_instance(&self, auth_instance: u64);
}
