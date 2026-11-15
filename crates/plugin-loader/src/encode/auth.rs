// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Auth request encoders and describe decoders (IF §8.8). W0-ABI stub: frozen signatures, `todo!()` bodies;
//! A7 fills it.

use busbar_plugin_abi::records::{Full, RecErr, Records, Writer};

use crate::ports::auth::{AuthIn, IssuedShape, LoginIn, UpstreamIn};

/// Round 12: D_ISSUED_KIND with its D_ISSUED_SHAPE (validated as §8.3 says), or None when neither is declared.
pub fn decode_issued_shape(
    describe: Records<'_>,
) -> Result<Option<(Box<str>, IssuedShape)>, RecErr> {
    let _ = describe;
    todo!()
}

pub fn encode_verify_io(
    w: &mut impl Writer,
    r: &AuthIn<'_>,
    issued: Option<&[u8]>,
) -> Result<(), Full> {
    let _ = (w, r, issued);
    todo!()
}

pub fn encode_login(w: &mut impl Writer, l: &LoginIn<'_>) -> Result<(), Full> {
    let _ = (w, l);
    todo!()
}

pub fn encode_outbound(w: &mut impl Writer, u: &UpstreamIn<'_>) -> Result<(), Full> {
    let _ = (w, u);
    todo!()
}
