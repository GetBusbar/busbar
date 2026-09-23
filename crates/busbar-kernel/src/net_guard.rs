// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Re-export shim over THE ONE NETWORK JUDGE, plus the one part of it a pure crate cannot hold.
//!
//! ## There was a second copy of this file, and the copy was a live bypass
//!
//! Until this commit `net_guard.rs` was 1,345 lines of guard — its own `METADATA_HOSTS`, its own
//! address predicates, its own WHATWG host extraction, its own resolve-then-pin — sitting beside a
//! near-identical 1,701-line definition in [`busbar_kernel_egress::trust::net`]. Two implementations
//! of one security control is not untidiness. It is the mechanism by which somebody hardens one and
//! the other keeps the hole, and it had already happened here twice: once inside this file (a
//! six-name metadata list shadowed privately inside `ssrf_blocked_host` while the module const the
//! DIALING path read held two), and once across the two files (the extraction was carried over
//! without the WHATWG leading/trailing trim, so `"https://10.99.99.99 "` read as a host that
//! matched no denylist entry while the connecting stack trimmed the space and dialled it).
//!
//! The first of those was the serious one, and it is worth naming exactly why: the address arm
//! cannot save a metadata endpoint that answers on a GLOBALLY ROUTABLE address.
//! `metadata.platformequinix.com` resolves and pins to a public literal, so
//! [`ip_is_cloud_metadata`] says nothing about it and [`judge_host_name`] — reading the short list —
//! said nothing either. NOTHING but the name arm can refuse that host, and the name arm was reading
//! the wrong list.
//!
//! So there is one definition now. It lives in the egress unit because #36 gives that unit "the
//! upstream leg — walk + swrr weighting + pre-dial guard; trust folded in", and because a guard
//! beside the walk is a guard every carrier reaches rather than one each transport must remember to
//! call. What is left here is a glob, so every in-core call site and all three plane crates keep
//! naming `busbar_kernel::net_guard::…` unchanged: this shim is what keeps a plane's reach pointed
//! at the kernel it already depends on instead of growing a new plane→unit edge.
//!
//! ## Why [`SystemResolver`] is here and the guard is not
//!
//! The guard is PURE — no I/O, no globals, one resolution taken through the [`Resolver`] seam — and
//! that purity is what lets it live in a crate whose entire dependency list is `busbar-contract`
//! plus `futures` (the spec holds the kernel-8 units to `⊆ {contract, plugin-sdk}`). A
//! `resolve_and_pin_async` that called `tokio::net::lookup_host` could not have moved there, and
//! for a while that one function was the stated reason the fork could not be collapsed.
//!
//! It was the wrong thing to move. A resolver is not a judgement; it is the thing the judgement is
//! applied to. So the async entry point is GONE rather than relocated, every caller funnels through
//! the one pure [`resolve_and_pin`], and the runtime-bound half — the actual `getaddrinfo` — is the
//! small binding below, in the crate that already owns tokio. The guard got smaller and the
//! constraint dissolved instead of being worked around.

pub use busbar_kernel_egress::trust::net::*;

use std::net::IpAddr;

/// THE REAL RESOLVER: the system resolver, reached through tokio, bound to the guard's seam.
///
/// This is what [`resolve_and_pin`] asks when the destination is a NAME rather than a literal, on
/// every path that used to call the deleted `resolve_and_pin_async`: the plane-host egress open,
/// the neutral full-duplex WS dial, the MCP dispatch pin and the OAuth2 client-ID-metadata fetch.
/// The ORDERING those paths depend on — structural refusals first so a hostile name never reaches a
/// resolver, then EXACTLY ONE lookup, then every answered address judged, then the pin — is stated
/// once, in [`resolve_and_pin`], and is not restated by any of them.
///
/// Returns EVERY address the name answered with, de-duplicated but otherwise untouched and
/// unsorted, which is the same rule the A2A card fetch's own resolver states. Filtering or
/// re-ordering would quietly decide which address the guard gets to judge, and the guard's rule is
/// that it judges all of them; de-duplication is not filtering, because a name answering the same
/// address under both a v4 and a v6 query is ONE fact and nothing distinct is dropped.
///
/// ## Why a thread of its own
///
/// The seam is synchronous, so this runs `getaddrinfo` and waits. Not
/// `Handle::current().block_on(..)` and not `block_in_place`: both make assumptions about the
/// caller (that there IS a runtime, that it is multi-threaded) that a synchronous seam cannot make,
/// and every one of the four callers reaches it from a different posture — a foreign thread already
/// inside `Runtime::block_on`, a boxed future on a shared worker, a plain `async fn`. A thread with
/// its own current-thread runtime has no such precondition and cannot panic on the caller's behalf.
/// This is the shape `busbar-a2a`'s card-fetch resolver already uses in production, stated once
/// more here rather than reached across a plane boundary for it.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        // Port zero: this seam answers about ADDRESSES. The port belongs to the URL and is applied
        // by the caller that built the pin, so asking the resolver about one would be asking a
        // second question.
        let target = format!("{host}:0");
        std::thread::scope(|s| {
            s.spawn(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("name lookup: could not start a runtime: {e}"))?;
                rt.block_on(async move {
                    let answered = tokio::net::lookup_host(target)
                        .await
                        .map_err(|e| e.to_string())?;
                    let mut out: Vec<IpAddr> = Vec::new();
                    for sa in answered {
                        let ip = sa.ip();
                        if !out.contains(&ip) {
                            out.push(ip);
                        }
                    }
                    Ok(out)
                })
            })
            .join()
            .map_err(|_| "name lookup: the worker thread panicked".to_string())?
        })
    }
}

#[cfg(test)]
#[path = "tests/net_guard_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/net_guard_fetch_tests.rs"]
mod fetch_tests;
