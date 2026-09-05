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
