// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Export request encoders and answer decoders (IF §8.8, round 33 §49). W0-ABI stub: frozen signatures,
//! `todo!()` bodies; A9 fills it.

use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::kinds::export::export::CustodyRec;
use busbar_plugin_abi::records::{Full, RecErr, Records, Writer};

use crate::ports::export::FamilyIn;

pub fn encode_batch(w: &mut impl Writer, lines: &[&[u8]]) -> Result<(), Full> {
    let _ = (w, lines);
    todo!()
}

pub fn encode_snapshot(w: &mut impl Writer, families: &[FamilyIn<'_>]) -> Result<(), Full> {
    let _ = (w, families);
    todo!()
}

/// Round 7: ACK, or APPEND then ACK (§8.5). Borrowed tail; the adapter copies only a non-empty tail.
/// Round 33: plus the optional CUSTODY after ACK. CUSTODY after APPEND, CUSTODY_NONE or a level above INDEXED,
/// a second CUSTODY, or `recheck_s > 0` when `confirm` (the image declared M_CONFIRM) is false: RecErr.
pub fn decode_delivered<'o>(
    a: &Answer<'o>,
    confirm: bool,
) -> Result<(u64, Option<(u32, &'o [u8])>, Option<CustodyRec>), RecErr> {
    let _ = (a, confirm);
    todo!()
}

/// Round 33: D_DELIVERY's `pending_capacity` (None when absent), with §8.5's describe rules checked in the
/// same pass as D_STREAMS and FB_SPAN_RECORDS: M_CONFIRM ⇔ D_DELIVERY, STREAM_CONTENT declared, no D_DEST_PATH,
/// ≥ 1, at most one. In 1.6.0 L7 calls it for the validation only; the value is kept from 1.6.x.
pub fn decode_delivery(describe: Records<'_>, methods: u64) -> Result<Option<u64>, RecErr> {
    let _ = (describe, methods);
    todo!()
}

/// Round 33: an export `open` answer's last CUSTODY (the ceiling): level 1..=3, `recheck_s` 0, at most one.
pub fn decode_ceiling(a: &Answer<'_>) -> Result<Option<u32>, RecErr> {
    let _ = a;
    todo!()
}
