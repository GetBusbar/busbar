// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The URL-GUARD family of the plane host-vtable: the host-owned STRUCTURAL SSRF guard for a
//! URL-shaped tool ARGUMENT.
//!
//! A model that has just read a hostile tool description can put `http://169.254.169.254/…` into a
//! tool ARGUMENT, and that argument is attacker-influenced DATA travelling to an operator-chosen
//! destination — the classic SSRF shape. Judging it means the tree's host primitives (the
//! `http(s)` scheme allowlist, the WHATWG host normalizer, the cloud-metadata / obfuscated-encoding
//! / internal-address checks), which live in the TRUST UNIT as
//! [`busbar_unit_trust::net::judge_literal`]. A plane compiled apart from the host cannot reach
//! them, and the neutral refusal CLASS the ABI carries is this crate's to speak. So the judgement
//! is a host-vtable slot: the plane passes the URL bytes and the target's private-addressing
//! policy, and the host returns an allow/deny verdict + the refusal class + the offending host
//! bytes. The DECISION is the unit's; only the classification is here.
//!
//! ## STRUCTURAL only — no name resolution
//!
//! The host judges the URL from the STRING alone and resolves NO name. For an argument the host is
//! NOT the connecting party — the upstream resolves the name itself, later, from its own resolver —
//! so a lookup here would be advisory at best (trivially defeated by rebinding, since nothing binds
//! our answer to the upstream's connect) while turning the host into a name-resolution oracle for
//! whatever a model types. The honest consequence is stated rather than softened: a hostname whose A
//! record points at loopback is NOT caught here. Adding resolution would CHANGE the answer, so it is
//! not added.
//!
//! ## Order is load-bearing, and it is stated where the arms are
//!
//! Metadata first and unconditionally, so a private-addressing target cannot reach the one endpoint
//! whose whole value to an attacker is that it hands out credentials. Obfuscated encodings next and
//! also unconditionally: a value spelled so the check cannot read it is refused rather than guessed
//! at. Internal addressing last, because that is the one a target can legitimately opt into. That
//! order is [`busbar_unit_trust::net::judge_host`]'s and is pinned by the unit's own cells — this
//! module no longer restates it, because an order written down twice is an order that can differ.

use super::{recover, with_borrowed_host, DispatchScope, HostState};
use crate::state::App;
use busbar_plugin::hot::host::HostCtx;
use busbar_plugin::hot::{GuardClass, GuardVerdict, StatusClass};
use busbar_unit_trust::net::{judge_literal, LiteralRefusal};
use core::mem::MaybeUninit;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// The outcome of a structural URL judgement driven over the host `guard_url` seam: admissible, or a
/// refusal carrying the neutral [`GuardClass`] and the offending host/url string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardOutcome {
    /// The URL is admissible.
    Allow,
    /// The URL is refused; `class` is the refusal shape and `reason` the offending host/url bytes.
    Deny {
        /// The neutral refusal class.
        class: GuardClass,
        /// The offending host (or the whole url, for a scheme/no-host refusal) the host copied back.
        reason: String,
    },
}

/// WIRED `guard_url` → the host-owned structural URL guard. Recovers the [`HostState`] (unused beyond
/// the recovery invariant — the judgement is a pure function of the URL and the policy), judges the
/// URL STRUCTURALLY, and writes the [`GuardVerdict`] into `out` on the `Ok` path, copying the
/// offending host/url bytes into `reason_buf` (up to `reason_cap`). `Refused` on a null / non-UTF-8
/// URL (`out` untouched); `Fault` on a caught panic (`out` untouched). The `extern "C-unwind"` ABI
/// shim that forwards into this lives in [`super::vtable`] (the boundary-discipline the other slots
/// follow: the pointer-taking body stays in the capability module, the shim is the seam).
pub(crate) fn guard_url(
    host: HostCtx,
    url_ptr: *const u8,
    url_len: usize,
    allow_private: u8,
    out: *mut MaybeUninit<GuardVerdict>,
    reason_buf: *mut u8,
    reason_cap: usize,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `recover`).
        let _state: &HostState = unsafe { recover(host) };
        if url_ptr.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: `(url_ptr, url_len)` is a live borrowed range for the call (ABI discipline).
        let bytes = unsafe { std::slice::from_raw_parts(url_ptr, url_len) };
        let Ok(url) = std::str::from_utf8(bytes) else {
            // A tool argument is a JSON string (always UTF-8); anything else is refused fail-closed,
            // leaving `out` untouched.
            return StatusClass::Refused;
        };
        let (verdict, class, reason) = match judge_url(url, allow_private != 0) {
            Ok(()) => (0u8, GuardClass::Allowed, String::new()),
            Err((class, reason)) => (1u8, class, reason),
        };
        // SAFETY: `reason_buf`/`reason_cap` are a writable range (or null) per the ABI.
        let reason_len = unsafe { write_reason(reason_buf, reason_cap, reason.as_bytes()) };
        let out_pod = GuardVerdict {
            size: core::mem::size_of::<GuardVerdict>() as u32,
            version: busbar_plugin::hot::POD_VERSION,
            _reserved: 0,
            verdict,
            class: class as u8,
            _reserved2: 0,
            reason_len: reason_len as u32,
        };
        // SAFETY: `out` is a writable, aligned `MaybeUninit<GuardVerdict>` slot (or null, tolerated);
        // the write publishes only on the Ok path (init-only-on-Ok).
        unsafe { busbar_plugin::write_out(out, out_pod) };
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault) // caught panic → the distinct fault class, never `Ok`.
}

/// Copy up to `cap` of `bytes` into the caller's `buf` (tolerating a null/zero-cap slot), returning
/// the number of bytes written — the offending-host read-back, sized by the caller exactly as the
/// `egress_fault` cause buffer is.
///
/// # Safety
/// `buf`, when non-null, is a writable range of at least `cap` bytes for the call.
unsafe fn write_reason(buf: *mut u8, cap: usize, bytes: &[u8]) -> usize {
    if buf.is_null() || cap == 0 {
        return 0;
    }
    let n = bytes.len().min(cap);
    // SAFETY: `bytes[..n]` is initialized and `buf[..n]` is a writable range (n ≤ cap, caller ABI).
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, n) };
    n
}

/// THE STRUCTURAL JUDGEMENT, which is the TRUST UNIT'S and is only CLASSIFIED here.
///
/// This module used to hold its own copy of the arms — the scheme allowlist, the metadata question,
/// the obfuscated-encoding check and the private-address check, composed here in this order. That
/// made it a third reading of a control the tree already had two of, and the one place the order of
/// those arms was written down twice. The decision is now asked of `busbar_unit_trust::net`, which
/// judges the UNRESOLVED authority structurally and resolves no name — the property this slot needs
/// and the reason it cannot use the resolving path (see the module header).
///
/// What stays here is the only part that is this crate's: mapping the unit's refusal onto the
/// neutral [`GuardClass`] the plugin ABI carries. The map is an IDENTITY, variant for variant,
/// because the unit's vocabulary was chosen to BE this one — a caller that had to interpret a
/// refusal would be a caller holding a second opinion about what the judge meant.
fn judge_url(url: &str, allow_private: bool) -> Result<(), (GuardClass, String)> {
    judge_literal(url, allow_private).map_err(|refusal| match refusal {
        LiteralRefusal::Scheme(url) => (GuardClass::Scheme, url),
        LiteralRefusal::NoHost(u) => (GuardClass::NoHost, u),
        LiteralRefusal::CloudMetadata(h) => (GuardClass::CloudMetadata, h),
        LiteralRefusal::ObfuscatedHost(h) => (GuardClass::ObfuscatedHost, h),
        LiteralRefusal::InternalHost(h) => (GuardClass::InternalHost, h),
    })
}

/// Reconstruct a [`GuardClass`] from the verdict's neutral class byte (the inverse of `class as u8`);
/// an unknown byte reads as [`GuardClass::Allowed`] (forward-compat, never a phantom refusal).
fn guard_class_from_u8(v: u8) -> GuardClass {
    match v {
        1 => GuardClass::Scheme,
        2 => GuardClass::NoHost,
        3 => GuardClass::CloudMetadata,
        4 => GuardClass::ObfuscatedHost,
        5 => GuardClass::InternalHost,
        _ => GuardClass::Allowed,
    }
}

/// Judge a URL-shaped tool argument through the host [`guard_url`] seam, returning the structural
/// verdict. `allow_private` is whether reaching internal hosts through this target is deliberate (the
/// target's `allow_private`). The judgement is STRUCTURAL and resolves no name (see the module
/// header). A SAFE wrapper that keeps the raw fn-pointer + `#[repr(C)]` out-param read inside this
/// audited module (busbar-core denies `unsafe` elsewhere). A fresh per-call [`DispatchScope`] backs
/// the borrow — a URL judgement acquires no host handle, so nothing outlives the call — mirroring
/// [`card_sign_over`](super::card_sign_over). A non-`Ok` status is fail-closed to a [`GuardOutcome::Deny`].
#[must_use]
pub fn guard_url_over(app: &App, url: &str, allow_private: bool) -> GuardOutcome {
    let scope = DispatchScope::new();
    let mut reason_buf = [0u8; 256];
    let mut out = MaybeUninit::<GuardVerdict>::uninit();
    let status = with_borrowed_host(app, &scope, |host, vt| {
        (vt.guard_url.expect("guard_url is a wired slot"))(
            host,
            url.as_ptr(),
            url.len(),
            u8::from(allow_private),
            std::ptr::from_mut(&mut out),
            reason_buf.as_mut_ptr(),
            reason_buf.len(),
        )
    });
    if status != StatusClass::Ok {
        // Fail-closed: an undecidable judgement denies rather than passing an unjudged URL through.
        return GuardOutcome::Deny {
            class: GuardClass::NoHost,
            reason: String::new(),
        };
    }
    // SAFETY: the `Ok` status published the out-param (init-only-on-Ok).
    let verdict = unsafe { out.assume_init() };
    if verdict.verdict == 0 {
        return GuardOutcome::Allow;
    }
    let n = (verdict.reason_len as usize).min(reason_buf.len());
    GuardOutcome::Deny {
        class: guard_class_from_u8(verdict.class),
        reason: String::from_utf8_lossy(&reason_buf[..n]).into_owned(),
    }
}
