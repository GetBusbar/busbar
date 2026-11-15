// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Hook request encoders and describe decoders (IF §8.8). W0-ABI stub: frozen signatures, `todo!()` bodies;
//! A8 fills it.

use busbar_plugin_abi::records::{Full, RecErr, Records, Writer};

use crate::ports::hook::HookView;

/// Round 12: every D_WORD item of one describe answer (validated: word grammar, at most 8, POINT_ROUTE declared).
pub fn decode_words(describe: Records<'_>) -> Result<Vec<Box<str>>, RecErr> {
    let _ = describe;
    todo!()
}

/// The view core builds once per decision point: signals, candidates, and the optional parts.
pub fn encode_view(w: &mut impl Writer, v: &HookView<'_>) -> Result<(), Full> {
    let _ = (w, v);
    todo!()
}
