// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Store request encoders and answer decoders (IF §8.8). W0-ABI stub: frozen signatures, `todo!()` bodies;
//! A5 fills it.

use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::records::{Full, RecErr, Writer};

pub fn encode_read(
    w: &mut impl Writer,
    r: &busbar_contract::persistence::Read,
) -> Result<(), Full> {
    let _ = (w, r);
    todo!()
}

pub fn encode_scan(
    w: &mut impl Writer,
    s: &busbar_contract::persistence::Scan,
) -> Result<(), Full> {
    let _ = (w, s);
    todo!()
}

/// Round 30: CAND_HEAD carries `key`'s slot and seq; the FENCE records are `control::fences(c)` (N9).
pub fn encode_candidate(
    w: &mut impl Writer,
    c: &busbar_contract::persistence::PreparedCandidate,
    key: &busbar_contract::persistence::CommitKey,
) -> Result<(), Full> {
    let _ = (w, c, key);
    todo!()
}

pub fn encode_dataset(
    w: &mut impl Writer,
    d: &busbar_contract::persistence::DatasetId,
) -> Result<(), Full> {
    let _ = (w, d);
    todo!()
}

pub fn decode_read(
    a: &Answer<'_>,
    n: usize,
) -> Result<busbar_contract::persistence::ReadResult, RecErr> {
    let _ = (a, n);
    todo!()
}

pub fn decode_page(a: &Answer<'_>) -> Result<busbar_contract::persistence::Page, RecErr> {
    let _ = a;
    todo!()
}

/// Round 30: COMMITTED code 1..=6 -> `Decision::{Applied, ConditionConflict, TimeGuardFailed{observed_at},
/// OpIdConflict, Fenced, Stale}` (f6e2cf05d7 persistence.rs:442-459); core supplies Applied's result from its own
/// candidate (N5); code 0 or ≥ 7 is RecErr::Size.
pub fn decode_decision(a: &Answer<'_>) -> Result<busbar_contract::persistence::Decision, RecErr> {
    let _ = a;
    todo!()
}

pub fn decode_clock(
    a: &Answer<'_>,
) -> Result<busbar_contract::persistence::ClockObservation, RecErr> {
    let _ = a;
    todo!()
}

/// Round 6: the `info` answer (exactly one INFO) as the kernel's BackendInfo; an unknown DUR_* is RecErr::Size.
pub fn decode_info(a: &Answer<'_>) -> Result<busbar_contract::persistence::BackendInfo, RecErr> {
    let _ = a;
    todo!()
}
