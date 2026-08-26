// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The INBOUND-IDENTITY seam of the plane host-vtable (minor-17), wired over core's REAL data-plane
//! admission: the configured auth chain ([`crate::auth::AuthMiddleware::run_chain_on_request_path`])
//! followed by the ONE verdict resolution ([`crate::auth::resolve_data_plane_identity`]) the HTTP
//! middleware itself runs — so a plane admits an inbound session WITHOUT naming `crate::auth`.
//!
//! ## The opaque handle — why the resolved identity does not cross as bytes
//!
//! The resolution yields a `(AuthPrincipal, PlaneRequestCtx)`: a neutral principal AND a
//! [`PlaneRequestCtx`](crate::governance::PlaneRequestCtx) carrying the resolved `Arc<VirtualKey>` —
//! the SENSITIVE enforcement key (its material, its group chain, its budget buckets). Neither is a
//! fixed-size POD, and the admission runs ONCE (the auth chain touches the credential cache and the
//! bounded offload pool — re-running it to re-marshal a field would be a second admission). So the
//! host STASHES the pair behind an opaque [`IdentityId`] (the `super::creds` / durable-scope
//! opaque-handle discipline) and the plane consumes it ONCE ([`take`]) to recover the EXACT objects —
//! byte-identical to the in-process resolution, with the gov key never crossing as bytes, only the
//! bare `u64` handle. A refusal stashes nothing and names [`IdentityId::NONE`].

use super::{recover, HostState};
use busbar_plugin::hot::host::HostCtx;
use busbar_plugin::hot::{
    IdentityAdmitted, IdentityId, IdentityOutcome, IdentityQuery, StatusClass, POD_VERSION,
};
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

/// The resolved inbound identity the host holds behind an [`IdentityId`]: the neutral principal and the
/// per-request governance context (the resolved key). Recovered ONCE by [`take`].
type Resolved = (
    crate::auth::AuthPrincipal,
    crate::governance::PlaneRequestCtx,
);

/// The process-wide resolved-identity registry, keyed by the opaque [`IdentityId`] the plane holds.
static REGISTRY: LazyLock<Mutex<HashMap<u64, Resolved>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The next identity handle. `0` is the reserved "none" handle (a refusal names it), so handles start
/// at `1`.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn registry() -> std::sync::MutexGuard<'static, HashMap<u64, Resolved>> {
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

/// Stash a resolved `(principal, gov)` and return the opaque [`IdentityId`] the plane carries back into
/// [`take`] — the ONLY thing about the resolved identity that crosses the seam. The gov key stays
/// host-side in the registry until consumed.
fn stash(resolved: Resolved) -> IdentityId {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    registry().insert(id, resolved);
    IdentityId(id)
}

/// Consume `id`, recovering the resolved `(principal, gov)` and REMOVING it from the registry (a handle
/// is single-use), or `None` when the handle is [`IdentityId::NONE`] or unknown (already consumed) — the
/// fail-closed reading the plane maps to a refusal.
#[must_use]
// Consumed only by `identity_admit_over` (MCP stdio inbound); no caller under a build without `plane-mcp`.
#[cfg_attr(not(feature = "plane-mcp"), allow(dead_code))]
pub(crate) fn take(id: IdentityId) -> Option<Resolved> {
    if id.is_none() {
        return None;
    }
    registry().remove(&id.0)
}

/// Read a borrowed `(ptr, len)` byte range into an owned `String` (lossy on non-UTF-8). A null pointer
/// or zero length reads as empty — the ABI's "not present" encoding for a borrowed field.
fn borrowed_string(ptr: *const u8, len: usize) -> String {
    if ptr.is_null() || len == 0 {
        return String::new();
    }
    // SAFETY: per the ABI borrow discipline a non-null `(ptr, len)` is a live, initialized byte range
    // for the duration of the host call (see the `IdentityQuery` field docs).
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf8_lossy(bytes).into_owned()
}

/// WIRED `identity_admit` → the REAL inbound admission over `crate::auth`: run the configured auth chain
/// over the caller's OWN wire credential (the [`IdentityQuery`]) and the live governance state, then the
/// ONE verdict resolution the HTTP middleware runs, and stash the resolved `(principal, gov)` behind an
/// opaque [`IdentityId`] on an admit. Writes the [`IdentityAdmitted`] out-param on `Ok`. Fail-closed:
/// [`StatusClass::Refused`] on a null query and [`StatusClass::Fault`] on any panic or a runtime that
/// will not start (`out` untouched on either — the plane refuses to admit).
///
/// The async chain is driven on a FRESH current-thread runtime (the egress precedent), so this sync
/// `extern "C-unwind"` slot bridges the async admission the same way the egress slots bridge their async
/// transport — the caller drives this slot from a blocking thread (see
/// [`super::identity_admit_over`](super)).
pub(crate) extern "C-unwind" fn identity_admit(
    host: HostCtx,
    query: *const IdentityQuery,
    out: *mut std::mem::MaybeUninit<IdentityAdmitted>,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `recover`).
        let state: &HostState = unsafe { recover(host) };
        if query.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: a non-null `query` is a live, initialized `IdentityQuery` for the call (ABI discipline).
        let q = unsafe { &*query };
        // The caller's OWN credential (None ⇒ the chain sees no candidate; distinct from empty).
        let candidate = if q.token_present != 0 {
            Some(borrowed_string(q.token_ptr, q.token_len))
        } else {
            None
        };
        // The expected audience (the resource canonical-uri the in-process door binds against). Absent ⇒
        // no audience expectation, matching an `expected_aud: None` chain call.
        let audience = borrowed_string(q.audience_ptr, q.audience_len);
        let expected_aud = (!audience.is_empty()).then_some(audience);
        let app = state.app;
        // Drive the ASYNC chain synchronously on a fresh current-thread runtime — the same async→sync
        // bridge the egress slots use (`run_http_stream`). A runtime that will not start is fail-closed.
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(_) => return StatusClass::Fault,
        };
        let verdict = rt.block_on(crate::auth::AuthMiddleware::run_chain_on_request_path(
            &app.auth,
            &app.credential_cache,
            candidate,
            app.governance.clone(),
            expected_aud,
        ));
        // THE ONE VERDICT RESOLUTION, shared with the HTTP middleware. An admit stashes the resolved
        // pair behind a fresh handle; a refusal keeps its SPECIFIC reason and names no handle.
        let (outcome, identity) = match crate::auth::resolve_data_plane_identity(app, verdict) {
            Ok(resolved) => (IdentityOutcome::Admitted, stash(resolved)),
            Err(crate::auth::IdentityRefusal::Denied) => {
                (IdentityOutcome::Denied, IdentityId::NONE)
            }
            Err(crate::auth::IdentityRefusal::NoGrant) => {
                (IdentityOutcome::NoGrant, IdentityId::NONE)
            }
        };
        let admitted = IdentityAdmitted {
            size: core::mem::size_of::<IdentityAdmitted>() as u32,
            version: POD_VERSION,
            outcome,
            _reserved: 0,
            _reserved2: 0,
            identity,
        };
        // SAFETY: `out` is a writable, aligned `MaybeUninit<IdentityAdmitted>` for the call (ABI); the
        // write publishes on the Ok path, tolerating a null slot.
        unsafe { busbar_plugin::write_out(out, admitted) };
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault) // caught panic → the distinct fault class, never `Ok`.
}

#[cfg(test)]
#[path = "tests/identity_admit_tests.rs"]
mod tests;
