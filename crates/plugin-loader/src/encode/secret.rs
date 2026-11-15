// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Secret request encoders and describe decoders (IF §8.8). W0-ABI stub: frozen signatures, `todo!()` bodies;
//! A6 fills it.

use busbar_plugin_abi::records::{Full, RecErr, Records, Writer};

use crate::ports::secret::SugarDecl;

pub fn encode_reference(w: &mut impl Writer, settings_json: &[u8]) -> Result<(), Full> {
    let _ = (w, settings_json);
    todo!()
}

/// Round 6: every D_SUGAR item of one describe answer (validated: word grammar, four TEXT, known role).
pub fn decode_sugars(describe: Records<'_>) -> Result<Vec<SugarDecl>, RecErr> {
    let _ = describe;
    todo!()
}
