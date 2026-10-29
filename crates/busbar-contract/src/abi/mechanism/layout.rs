// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KIND LAYOUT FINGERPRINT (status row 188): one number per kind ABI that moves whenever a
//! `#[repr(C)]` struct crossing that kind's table changes its size, its alignment or the offset of
//! any of its fields.
//!
//! A kind's version number moves only when a person moves it; a layout can move under it (a field
//! inserted into the hook `RequestView` shifted every later field of `DecideIn` by 24 bytes and
//! left the hook ABI version where it was). The fingerprint is derived from the layout itself, so
//! it cannot be forgotten: each kind states its own as `abi/<kind>/`'s `LAYOUT_FINGERPRINT`, the
//! door carries the number the plugin was built with ([`super::door::Door::layout`]), and the
//! loader refuses a door whose number is not the host's, for every kind and both origins.
//!
//! THE FOLD. Each struct is its words: its size, its alignment, then each field's offset, in the
//! order the kind's `LAYOUT_SHAPES` lists them ([`crate::layout_shape!`]). The kind's structs are
//! folded in their listed order: per struct, its word count, then its words, each folded whole into
//! a 64-bit FNV-1a state ([`fingerprint`]). The fold is `const`: `LAYOUT_SHAPES` is evaluated by the
//! compiler from `size_of`, `align_of` and `offset_of!`, never written by hand. The number each
//! kind states is a literal (the generated C header carries it to a plugin built from the header
//! alone), and `tests/layout_fingerprint.rs` holds every literal to its fold, naming the fold's
//! number when they part.

/// The FNV-1a offset basis the fold starts from.
const FOLD_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
/// The FNV-1a prime each folded word is multiplied by.
const FOLD_PRIME: u64 = 0x0000_0100_0000_01b3;

/// One word folded into the state.
#[must_use]
pub const fn fold(state: u64, word: u64) -> u64 {
    (state ^ word).wrapping_mul(FOLD_PRIME)
}

/// THE FINGERPRINT of a kind's shapes: per shape, its word count, then its words, folded in order
/// from the FNV-1a offset basis.
#[must_use]
pub const fn fingerprint(shapes: &[&[u64]]) -> u64 {
    let mut state = FOLD_BASIS;
    let mut s = 0;
    while s < shapes.len() {
        let words = shapes[s];
        state = fold(state, words.len() as u64);
        let mut w = 0;
        while w < words.len() {
            state = fold(state, words[w]);
            w += 1;
        }
        s += 1;
    }
    state
}

/// THE WORDS OF ONE STRUCT for a kind's `LAYOUT_SHAPES`: `layout_shape!(Type => field, …)` is
/// `&[size_of, align_of, offset_of!(Type, field), …]`, every word a `u64`, evaluated by the
/// compiler. A field left out of the list is a field the fingerprint does not see, so the list
/// names every field, in declaration order.
#[macro_export]
macro_rules! layout_shape {
    ($t:ty => $($field:ident),* $(,)?) => {
        &[
            ::core::mem::size_of::<$t>() as u64,
            ::core::mem::align_of::<$t>() as u64,
            $(::core::mem::offset_of!($t, $field) as u64,)*
        ]
    };
}
