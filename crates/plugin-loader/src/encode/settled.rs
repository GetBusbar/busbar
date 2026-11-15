// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The settled part of an `open` answer, every kind (IF §8.8, round 31 §47, round 33 §49). W0-ABI stub: frozen
//! signatures, `todo!()` bodies; A5 fills it.

use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::records::{RecErr, Records};

use crate::ports::SettledOut;

pub fn decode_settled<'o>(a: &Answer<'o>) -> Result<Option<SettledOut<'o>>, RecErr> {
    let _ = a;
    todo!()
}

/// The grammar behind [`decode_settled`], over the answer's records (TOKEN already excluded).
fn settled_records<'o>(recs: Records<'o>) -> Result<Option<SettledOut<'o>>, RecErr> {
    let _ = recs;
    todo!()
}

#[cfg(test)]
#[path = "settled_tests.rs"]
mod tests;
