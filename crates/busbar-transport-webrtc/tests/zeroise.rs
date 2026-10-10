// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! KEYS ARE ZEROISED (THE DESIGN l.753): the keying material the framer holds is cleared before
//! its memory goes back to the allocator, whether it was held to the end or refused.
//!
//! THE WITNESS is this binary's allocator: every block freed is read first, and a block still
//! holding a marked key (eight marker bytes, then the key's id 48 times) is counted against that
//! id. Each test marks its own id, so tests running side by side never count each other's frees.
//!
//! THE RED ARM, kept: the same marked key in a plain `Vec`, dropped, IS seen, so a zero count
//! below is the zeroising, never a witness that cannot see.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use busbar_transport_webrtc::framing::{Framing, Opening, Side, PROFILE_AEAD_AES_128_GCM};
use busbar_transport_webrtc::shim::Shim;

const MARK: [u8; 8] = *b"ZEROISE!";
/// A key: the marker and 48 bytes of its id (the AEAD-AES-128-GCM material's 56 bytes).
const KEY_LEN: usize = 56;
const IDS: usize = 8;

static FREED_UNZEROED: [AtomicUsize; IDS] = [const { AtomicUsize::new(0) }; IDS];

/// The system allocator, reading every block it frees for a marked key.
struct Watch;

/// The id of the marked key at the start of `w`, if one is there whole.
fn marked(w: &[u8]) -> Option<usize> {
    let (mark, rest) = w.split_at_checked(MARK.len())?;
    let id = *rest.first()?;
    (mark == MARK && rest.len() >= KEY_LEN - MARK.len() && rest[..KEY_LEN - MARK.len()].iter().all(|b| *b == id))
        .then_some(usize::from(id))
        .filter(|id| *id < IDS)
}

// SAFETY: every call is forwarded to `System` with its own arguments; `dealloc` only reads the
// block it is handed before forwarding.
unsafe impl GlobalAlloc for Watch {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() >= KEY_LEN {
            // SAFETY: `ptr` is a live block of `layout.size()` bytes until `System` frees it below,
            // and its owner has given it up: nothing else reads or writes it during `dealloc`. It
            // is read as plain bytes and nothing read is kept.
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            for at in 0..=block.len() - KEY_LEN {
                if block[at] == MARK[0] {
                    if let Some(id) = marked(&block[at..]) {
                        FREED_UNZEROED[id].fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        }
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static WATCH: Watch = Watch;

/// The marked key `id`, on the stack (the stack is not the allocator's to watch).
fn key(id: u8) -> [u8; KEY_LEN] {
    let mut k = [id; KEY_LEN];
    k[..MARK.len()].copy_from_slice(&MARK);
    k
}

fn freed_unzeroed(id: u8) -> usize {
    FREED_UNZEROED[usize::from(id)].load(Ordering::SeqCst)
}

#[test]
fn keying_material_held_by_the_shim_is_zeroised_when_it_drops() {
    let material = key(1);
    let shim = Shim::default();
    shim.keyed(&material, PROFILE_AEAD_AES_128_GCM)
        .expect("AEAD-AES-128-GCM is taken");
    assert!(shim.holds_keying(), "the material was held, on the heap");
    drop(shim);
    assert_eq!(freed_unzeroed(1), 0, "the held material was freed unzeroed");
}

#[test]
fn keying_material_a_framing_refuses_is_zeroised() {
    let material = key(2);
    let now = Instant::now();
    let mut f = Framing::begin(
        Side::Accept,
        b"public certificate bytes",
        Some("203.0.113.9:3478".parse().expect("an address")),
        &Opening::default(),
        now,
    )
    .expect("begins");
    // Keying before verification: the framing copies the item, refuses it, and holds nothing.
    assert!(f
        .host(0, false, Some((PROFILE_AEAD_AES_128_GCM, &material)), now)
        .is_err());
    assert!(!f.holds_keying());
    // AES_CM, verified: refused the same way.
    assert!(f.host(0, true, Some((0x0001, &material)), now).is_err());
    assert!(!f.holds_keying());
    drop(f);
    assert_eq!(freed_unzeroed(2), 0, "a refused item was freed unzeroed");
}

#[test]
fn red_arm_a_key_in_a_plain_vec_is_seen_freed_unzeroed() {
    let material = key(3);
    let plain: Vec<u8> = material.to_vec();
    drop(std::hint::black_box(plain));
    assert!(
        freed_unzeroed(3) >= 1,
        "the witness must see a key freed without zeroising"
    );
    // And a zeroising holder of the same bytes is not seen.
    let held = zeroize::Zeroizing::new(key(4).to_vec());
    drop(std::hint::black_box(held));
    assert_eq!(freed_unzeroed(4), 0);
}
