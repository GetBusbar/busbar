// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KIND LAYOUT FINGERPRINT: one number per kind ABI that moves whenever a

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
