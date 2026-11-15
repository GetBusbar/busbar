// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Transport request encoders and answer decoders (IF §8.8). W0-ABI stub: frozen signatures, `todo!()` bodies;
//! A11 fills it.

use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::records::{Full, RecErr, Writer};

pub fn encode_path(w: &mut impl Writer, path: u32, flags: u32, addr: &str) -> Result<(), Full> {
    let _ = (w, path, flags, addr);
    todo!()
}

pub fn encode_keying(
    w: &mut impl Writer,
    path: u32,
    profile: u32,
    material: &[u8],
) -> Result<(), Full> {
    let _ = (w, path, profile, material);
    todo!()
}

/// Round 9: the `offer` answer (ALPN*, each 1..=255 bytes, at most 8). Round 22: then, for ROLE_CLIENT only,
/// PAIR* (at most 8, names lowercase token characters, values without CR/LF) as `defaults`; anything else,
/// or PAIR for ROLE_SERVER, BadRecords.
pub fn decode_offer(a: &Answer<'_>, role: u32) -> Result<Offer, RecErr> {
    let _ = (a, role);
    todo!()
}

pub struct Offer {
    pub alpn: Box<[Box<str>]>,
    pub defaults: Box<[(Box<str>, Box<str>)]>,
}
