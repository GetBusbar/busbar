// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `observe_wipe` for the wiping buffer's tests (moved from busbar-core-connector's test support),
//! over this crate's own observing allocator ([`crate::alloc_counter`]).

use crate::alloc_counter::{watch_initialized_payload, InitializedPayloadProbe};

/// Run `run` and report whether the allocation at `pointer` (its first `len` initialized bytes)
/// was all zero when it was freed: `(result, Some(wiped) if freed, None)`.
pub(crate) fn observe_wipe<T>(
    pointer: *const u8,
    len: usize,
    run: impl FnOnce() -> T,
) -> (T, Option<bool>, Option<bool>) {
    // SAFETY: the caller names the base of a live allocation it owns exclusively, `len` bytes of
    // it initialized, freed (if at all) on this thread inside `run`.
    #[allow(unsafe_code)]
    let probe = unsafe { InitializedPayloadProbe::start() }.expect("the payload probe starts");
    // SAFETY: as above; the slice is read only while the owner still holds the allocation.
    #[allow(unsafe_code)]
    unsafe {
        watch_initialized_payload(std::slice::from_raw_parts(pointer, len));
    }
    let result = run();
    let observed = probe.finish();
    let first = observed
        .payloads
        .first()
        .filter(|payload| payload.freed)
        .map(|payload| payload.wiped && payload.complete_read);
    (result, first, None)
}

// The crate's one test owner seal, for the tests that only name an owner type: a seal minted in
// each such module would leave its `here()` unused.
crate::own_seal!(Own);
