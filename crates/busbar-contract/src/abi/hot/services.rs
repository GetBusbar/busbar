// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST SERVICES ACROSS THE HOT SEAM (minor 30; ARCHITECT SD-3 queue (6), DEC-SERVE G2).
//!
//! The contract ports a codec reaches — [`fill_entropy`](crate::codec::fill_entropy),
//! [`wall_clock_now`](crate::codec::wall_clock_now),
//! [`usage_tap_fault_should_warn`](crate::codec::usage_tap_fault_should_warn) and
//! [`max_translate_body_bytes`](crate::codec::max_translate_body_bytes) — are process-wide
//! `OnceLock`s the host arms in ITS image. A plane LINKED into the host shares that image, so it
//! reads the host's services. A plane DROPPED IN as a `cdylib` carries its own copy of this crate,
//! whose ports nothing armed: it read the failure path of every one (a synthesized id with no
//! entropy, an unstamped time, a latch that never warns, the default cap instead of the operator's).
//!
//! Two halves, one file, because they are one contract:
//!
//! * **HOST side** — `entropy_fill`, `wall_clock`, `tap_fault_latch`, `translate_cap`: the
//!   four slots of [`PlaneHostVtable::SERVICES`], each answering from THIS image's own ports, which
//!   the host armed. A host that builds its table over `SERVICES` adds no code of its own.
//! * **PLANE side** — [`arm`]: run in a dropped-in plane's image (the door's `busbar_plane_arm`
//!   symbol, which the host calls when it opens the door), it installs that image's ports over the
//!   host's slots, so a codec in the plane reads the host's services exactly as a linked codec does.

use super::host::{HostCtx, PlaneHostVtable};
use super::pod::StatusClass;
use std::panic::catch_unwind;
use std::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

// ── HOST SIDE: the four slots, served from this image's armed contract ports ────────────────────────

/// `entropy_fill` — fill `out_len` bytes at `out` through [`crate::codec::fill_entropy`].
pub(crate) extern "C-unwind" fn entropy_fill(
    _host: HostCtx,
    out: *mut u8,
    out_len: usize,
) -> StatusClass {
    catch_unwind(|| {
        if out.is_null() && out_len > 0 {
            return StatusClass::Refused;
        }
        let buf: &mut [u8] = if out_len == 0 {
            &mut []
        } else {
            // SAFETY: a non-null `out` addresses `out_len` writable bytes for the call (the slot's
            // buffer discipline).
            unsafe { core::slice::from_raw_parts_mut(out, out_len) }
        };
        if crate::codec::fill_entropy(buf) {
            StatusClass::Ok
        } else {
            StatusClass::Refused
        }
    })
    .unwrap_or(StatusClass::Fault)
}

/// `wall_clock` — [`crate::codec::wall_clock_now`], `0` when the host armed no clock.
pub(crate) extern "C-unwind" fn wall_clock(_host: HostCtx) -> u64 {
    catch_unwind(|| crate::codec::wall_clock_now().unwrap_or(0)).unwrap_or(0)
}

/// `tap_fault_latch` — [`crate::codec::usage_tap_fault_should_warn`] over the two borrowed ranges.
/// The port takes the reason as `&'static str` (a codec names its reasons as constants), so a
/// reason crossing from a plane image is kept once per distinct spelling, up to [`REASON_CAP`];
/// past the cap every new spelling counts as [`UNLISTED_REASON`], so a plane cannot grow the host's
/// memory or its label set without bound.
pub(crate) extern "C-unwind" fn tap_fault_latch(
    _host: HostCtx,
    protocol_ptr: *const u8,
    protocol_len: usize,
    reason_ptr: *const u8,
    reason_len: usize,
) -> bool {
    catch_unwind(|| {
        // SAFETY (both): each range is live and initialized for the call (the slot's discipline).
        let (Some(protocol), Some(reason)) =
            (unsafe { utf8(protocol_ptr, protocol_len) }, unsafe {
                utf8(reason_ptr, reason_len)
            })
        else {
            return false;
        };
        crate::codec::usage_tap_fault_should_warn(protocol, kept(reason))
    })
    .unwrap_or(false)
}

/// `translate_cap` — [`crate::codec::max_translate_body_bytes`].
pub(crate) extern "C-unwind" fn translate_cap(_host: HostCtx) -> u64 {
    catch_unwind(|| crate::codec::max_translate_body_bytes() as u64)
        .unwrap_or(crate::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT as u64)
}

/// How many distinct usage-tap reasons the host keeps for planes (a codec declares a handful).
pub const REASON_CAP: usize = 64;

/// The reason every spelling past [`REASON_CAP`] counts as.
pub const UNLISTED_REASON: &str = "unlisted";

/// `reason`, kept for the life of the process (once per spelling; see [`tap_fault_latch`]), in a
/// fixed table of [`REASON_CAP`] process-lifetime slots — nothing is leaked, and the table cannot grow.
fn kept(reason: &str) -> &'static str {
    static KEPT: [std::sync::OnceLock<String>; REASON_CAP] =
        [const { std::sync::OnceLock::new() }; REASON_CAP];
    static FILLING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _filling = FILLING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for slot in &KEPT {
        match slot.get() {
            Some(kept) if kept == reason => return kept.as_str(),
            Some(_) => {}
            None => return slot.get_or_init(|| reason.to_owned()).as_str(),
        }
    }
    UNLISTED_REASON
}

/// A borrowed range as UTF-8; `None` for a NULL range with a length, or bytes that are not UTF-8.
///
/// # Safety
/// A non-null `ptr` must address `len` live, initialized bytes for `'a`.
unsafe fn utf8<'a>(ptr: *const u8, len: usize) -> Option<&'a str> {
    if len == 0 {
        return Some("");
    }
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the caller's obligation.
    std::str::from_utf8(unsafe { core::slice::from_raw_parts(ptr, len) }).ok()
}

// ── PLANE SIDE: arm this image's ports over the host's slots ────────────────────────────────────────

/// The host table [`arm`] was handed, and the size [`PlaneHostVtable::check`] honoured for it.
static ARMED: AtomicPtr<PlaneHostVtable> = AtomicPtr::new(core::ptr::null_mut());
static ARMED_SIZE: AtomicU32 = AtomicU32::new(0);

/// ARM THIS IMAGE'S CONTRACT PORTS over the host's service slots: check `host` (the airlock, plane
/// side), keep it, and install each port whose slot the host granted with a forwarder that calls
/// through that slot. A port whose slot is absent is left as it was (its failure path). The ports
/// are first-install-wins, so the first arm in an image is the one that holds; a host's table is
/// `'static`, so it stays callable for the image's life.
///
/// [`StatusClass::Ok`] when armed; [`StatusClass::Refused`] for a NULL table or one the airlock
/// refuses, and [`StatusClass::Unsupported`] for a table that serves from THIS image (nothing
/// installed on either).
///
/// # Safety
/// A non-null `host` must address a live `PlaneHostVtable` that outlives this image (a host's
/// `'static` table).
pub unsafe fn arm(host: *const PlaneHostVtable) -> StatusClass {
    if host.is_null() {
        return StatusClass::Refused;
    }
    // SAFETY: the caller's obligation; `check` reads only the frozen header by address.
    let Ok(size) = (unsafe { PlaneHostVtable::check(host) }) else {
        return StatusClass::Refused;
    };
    // SAFETY: as below — `host`/`size` are what `check` just validated.
    let own = crate::host_slot!(host, size, entropy_fill)
        .is_some_and(|fill| fill as usize == entropy_fill as super::host::EntropyFillFn as usize);
    if own {
        // The host IS this image (a linked plane): its ports are the host's own, armed by the host,
        // and a forwarder installed here would call back into itself.
        return StatusClass::Unsupported;
    }
    ARMED_SIZE.store(size, Ordering::Release);
    ARMED.store(host.cast_mut(), Ordering::Release);
    // SAFETY (all four): `host`/`size` are what `check` just validated.
    if crate::host_slot!(host, size, entropy_fill).is_some() {
        crate::codec::install_entropy_source(armed_entropy);
    }
    if crate::host_slot!(host, size, wall_clock).is_some() {
        crate::codec::install_wall_clock(armed_wall_clock);
    }
    if crate::host_slot!(host, size, tap_fault_latch).is_some() {
        crate::codec::install_usage_tap_fault_latch(armed_tap_fault_latch);
    }
    if crate::host_slot!(host, size, translate_cap).is_some() {
        crate::codec::install_translate_cap_reader(armed_translate_cap);
    }
    StatusClass::Ok
}

/// The armed table and its honoured size, once [`arm`] ran.
fn armed() -> Option<(*const PlaneHostVtable, u32)> {
    let host = ARMED.load(Ordering::Acquire);
    (!host.is_null()).then(|| (host.cast_const(), ARMED_SIZE.load(Ordering::Acquire)))
}

/// The entropy port, forwarded through the host's `entropy_fill`.
fn armed_entropy(out: &mut [u8]) -> bool {
    let Some((host, size)) = armed() else {
        return false;
    };
    // SAFETY: `host`/`size` were validated by `arm` over a table that outlives the image.
    let Some(fill) = crate::host_slot!(host, size, entropy_fill) else {
        return false;
    };
    fill(HostCtx::NULL, out.as_mut_ptr(), out.len()) == StatusClass::Ok
}

/// The wall-clock port, forwarded through the host's `wall_clock`.
fn armed_wall_clock() -> u64 {
    // SAFETY: as `armed_entropy`.
    armed()
        .and_then(|(host, size)| crate::host_slot!(host, size, wall_clock))
        .map_or(0, |now| now(HostCtx::NULL))
}

/// The usage-tap latch port, forwarded through the host's `tap_fault_latch`.
fn armed_tap_fault_latch(protocol: &str, reason: &'static str) -> bool {
    // SAFETY: as `armed_entropy`.
    armed()
        .and_then(|(host, size)| crate::host_slot!(host, size, tap_fault_latch))
        .is_some_and(|latch| {
            latch(
                HostCtx::NULL,
                protocol.as_ptr(),
                protocol.len(),
                reason.as_ptr(),
                reason.len(),
            )
        })
}

/// The translate-cap port, forwarded through the host's `translate_cap`.
fn armed_translate_cap() -> usize {
    // SAFETY: as `armed_entropy`.
    armed()
        .and_then(|(host, size)| crate::host_slot!(host, size, translate_cap))
        .map_or(crate::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT, |cap| {
            usize::try_from(cap(HostCtx::NULL)).unwrap_or(usize::MAX)
        })
}

#[cfg(test)]
#[path = "tests/services_tests.rs"]
mod tests;
