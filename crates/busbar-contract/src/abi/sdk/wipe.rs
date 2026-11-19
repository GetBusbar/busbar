// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Wiping byte buffers: the whole allocation is zeroed with volatile stores before it is freed.

/// Wipe every byte of `bytes`' allocation, its whole capacity as `Zeroize for Vec<u8>` does, and
/// leave it empty. The same guarantee (volatile zero stores the compiler may not elide, then a
/// fence), stored a word at a time: `Vec<u8>`'s own `zeroize` stores and fences byte by byte,
/// which is what a 4 KiB per-call output buffer spends most of its life on.
pub fn wipe_bytes(bytes: &mut Vec<u8>) {
    bytes.clear();
    wipe_spare(bytes.spare_capacity_mut());
}

fn wipe_spare(spare: &mut [core::mem::MaybeUninit<u8>]) {
    use core::mem::MaybeUninit;
    // SAFETY: `MaybeUninit<u8>` and `MaybeUninit<u64>` carry no validity invariant, so viewing the
    // aligned middle of the region as words is sound; `align_to_mut` puts every byte in exactly
    // one of the three parts and borrows the region exclusively.
    let (head, words, tail) = unsafe { spare.align_to_mut::<MaybeUninit<u64>>() };
    for byte in head.iter_mut().chain(tail.iter_mut()) {
        // SAFETY: an exclusive, aligned reference into the live allocation.
        unsafe { core::ptr::write_volatile(byte, MaybeUninit::new(0)) };
    }
    for word in words {
        // SAFETY: an exclusive, aligned reference into the live allocation.
        unsafe { core::ptr::write_volatile(word, MaybeUninit::new(0)) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// A byte buffer that wipes its whole allocation when it drops (or is zeroized), through
/// [`wipe_bytes`], for per-call buffers. It derefs to the bytes as a slice only: a holder replaces
/// the buffer whole and never grows it in place.
#[derive(Default)]
pub struct WipedBytes(Vec<u8>);

impl core::fmt::Debug for WipedBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "WipedBytes([REDACTED; {}])", self.0.len())
    }
}

impl WipedBytes {
    /// Take ownership of `bytes`; they are wiped when this drops.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The allocation's capacity, every byte of which is wiped.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.0.capacity()
    }
}

impl core::ops::Deref for WipedBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl core::ops::DerefMut for WipedBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl zeroize::Zeroize for WipedBytes {
    fn zeroize(&mut self) {
        wipe_bytes(&mut self.0);
    }
}

impl Drop for WipedBytes {
    fn drop(&mut self) {
        wipe_bytes(&mut self.0);
    }
}

impl zeroize::ZeroizeOnDrop for WipedBytes {}

/// A reply head that wipes its status, reason, fields and body when it drops: the field type of
/// [`ProtectedResponse::head`](super::exchange::ProtectedResponse::head), the exchange's reply and
/// [`ExchangeFailure`](super::exchange::ExchangeFailure)'s head. `ExchangeResponse` itself has no
/// `Drop`, so its fields still move out (`reply.body`); this holder wipes whatever is left.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ResponseHead(super::exchange::ExchangeResponse);

impl ResponseHead {
    /// Take ownership of `response`; it is wiped when this drops.
    #[must_use]
    pub fn new(response: super::exchange::ExchangeResponse) -> Self {
        Self(response)
    }
}

impl From<super::exchange::ExchangeResponse> for ResponseHead {
    fn from(response: super::exchange::ExchangeResponse) -> Self {
        Self(response)
    }
}

impl core::fmt::Debug for ResponseHead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.0, f)
    }
}

impl core::ops::Deref for ResponseHead {
    type Target = super::exchange::ExchangeResponse;
    fn deref(&self) -> &super::exchange::ExchangeResponse {
        &self.0
    }
}

impl core::ops::DerefMut for ResponseHead {
    fn deref_mut(&mut self) -> &mut super::exchange::ExchangeResponse {
        &mut self.0
    }
}

impl zeroize::Zeroize for ResponseHead {
    fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl Drop for ResponseHead {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl zeroize::ZeroizeOnDrop for ResponseHead {}

/// A conditional plane request is secret in every instance: it wipes its candidate on drop. The
/// body lives here, outside the request-path tree.
impl Drop for super::plane::conditional::Request {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

impl zeroize::ZeroizeOnDrop for super::plane::conditional::Request {}

