// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A PLANE'S READS OF A BODY BY DECLARED POINTER, one copy for every plane (ARCHITECT round 4
//! Q-L3B-GATES (4): identical logic is hoisted into the plane SDK). Every reader goes through the
//! contract's own span grammar ([`crate::spans`]), the kernel's: a plane that carried a scanner of
//! its own would be a closed grammar with a second reading.

use crate::bounded::{Ir, PlaneAlloc};
use crate::wire::Decode;

/// The span view of a body, built from the pointers a plane declared: one scan of one closed
/// grammar, into the unit's own arena, so the loop reads the spans the plane resolved instead of
/// walking the same bytes a second time. The arena refusing is a decode failure at the step that
/// asked for the bytes, which is what the arena's budget means.
///
/// # Errors
///
/// [`Decode::Oversize`] when the arena refuses the spans.
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
