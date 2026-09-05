//! The closed JSON span grammar, on the plugin surface.
//!
//! One serialization, one scanner, one reading. The grammar itself is [`busbar_grammar`], a crate
//! that names nothing of busbar's; this module is how a plugin reaches it, so a plane resolving the
//! pointers it declared and the kernel resolving the same pointers are the same walk over the same
//! bytes. Before this existed the contract handed a plane no scanner at all, and four planes each
//! carried their own approximation of a grammar the design says is closed.
//!
//! A pointer resolves to a [`Span`] of the CALLER's bytes: nothing is parsed into a document,
//! nothing is copied, and nothing is allocated by the scan itself.

pub use busbar_grammar::{resolve_pointer, scan_frontier, Resolved, Span, MAX_JSON_DEPTH};

use crate::bounded::{Arena, ArenaBudget, MAX_KEYS};

/// Resolve a plane's declared pointers over a body, into a table the unit can hold.
///
/// This is the whole of what a plane needs from the grammar. It walks the body once per pointer,
/// keeps only the pointers that RESOLVED — a pointer the body does not carry is absent from the
/// table rather than present and empty, because "the client sent nothing" and "the client sent
/// something empty" are different facts the loop settles differently — and copies the resulting
/// pairs into the arena so the table lives as long as the unit that reads it.
///
/// At most [`MAX_KEYS`] pointers are considered, which is the same ceiling the fact map carries: a
/// plane that declared more places than the kernel can hold facts about is describing a body no
/// unit could be settled against.
///
/// # Errors
/// The arena had no room for the table.
pub fn resolve<'a>(
    body: &[u8],
    pointers: &[&'a str],
    arena: &'a dyn Arena,
) -> Result<&'a [(&'a str, Span)], ArenaBudget> {
    let mut found: [(&'a str, Span); MAX_KEYS] = [("", Span::new(0, 0)); MAX_KEYS];
    let mut len = 0usize;
    for pointer in pointers.iter().take(MAX_KEYS) {
        if let Resolved::Found(span) = resolve_pointer(body, pointer) {
            found[len] = (*pointer, span);
            len += 1;
        }
    }
    arena.alloc_spans(&found[..len])
}
