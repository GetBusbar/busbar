// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared plane-SDK readers for a body declared

use crate::bounded::{Ir, PlaneAlloc};
use crate::wire::Decode;

/// The span view of a body, built from the pointers a plane declared: one scan of one closed
pub fn view_with_arena<'u>(
    body: &'u [u8],
    pointers: &[&'u str],
    arena: &'u dyn PlaneAlloc,
) -> Result<Ir<'u>, Decode> {
    let spans = crate::spans::resolve(body, pointers, arena).map_err(|_| Decode::Oversize)?;
    Ok(Ir::new(body, spans))
}

/// Whether a body has a member at one pointer at all.
#[must_use]
pub fn has(body: &[u8], pointer: &str) -> bool {
    read_raw(body, pointer).is_some()
}

/// The raw bytes at one pointer of a body.
#[must_use]
pub fn read_raw<'u>(body: &'u [u8], pointer: &str) -> Option<&'u [u8]> {
    match crate::spans::resolve_pointer(body, pointer) {
        crate::spans::Resolved::Found(span) => body.get(span.start..span.end),
        _ => None,
    }
}
