// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The closed grammars: where a claim can match, where a credential can be found, and the one
//! serialization the kernel understands.
//!
//! Everything a plugin varies is a key into a registry. Everything STRUCTURAL is closed, and this
//! is where the loop NAMES the closed structures. There are three of them, and the kernel owns
//! none of them outright any more:
//!
//! - **Selectors** — the forms a claim may match on. A plane says "these bytes are mine" only in
//!   one of these shapes, which is what makes "can two claims both match?" a question with an
//!   answer rather than an opinion. Declared by the contract, along with every per-form fact:
//!   which part of a request a form reads, whether two selectors overlap, whether one matches an
//!   arriving request, and how specific it is. What stays with the kernel is the APPLICATION of
//!   the last of those — the sealed order a plane's claims are tried in, which is a decision about
//!   claims and not a fact about a selector.
//! - **Locations** — the forms a credential or an idempotency key may be found at. Each form also
//!   says how it is masked, so hiding a credential is decided by the grammar and not per plane.
//!   Declared by the contract.
//! - **The JSON span scanner** — one crate, [`busbar_grammar`], named here and re-exported by the
//!   contract as `busbar_contract::spans`. The kernel reads exactly one serialization, and it reads
//!   it without allocating and without copying: a pointer resolves to a SPAN of the caller's own
//!   bytes. It lives on its own so that a plane resolving its declared pointers and the loop
//!   resolving the same pointers are the same walk over the same bytes, not two readings that agree
//!   until they do not.

/// The claim grammar and the credential grammar, as the contract crate declares them.
///
/// Both are plugin-visible: a plane writes its claims and an auth scheme names where its credential
/// lives, so the kernel evaluates values that arrived from outside it. It does not get a second
/// spelling of them. The contract owns the shapes, the overlap decision, the form-to-family map and
/// the masking rule.
pub use busbar_contract::{
    ArrivalLocation, Location, MaskKind, PathSeg as Segment, Selector, SelectorFamily,
    SelectorForm, SignedOver,
};

/// The closed JSON span grammar, named rather than spelled a second time.
///
/// The scanner is [`busbar_grammar`]'s, and the contract re-exports the same crate, so the pointer
/// a plane resolved and the pointer the pump resolves are resolved by one reading of one grammar.
pub use busbar_grammar::{resolve_pointer, scan_frontier, Resolved, Span, MAX_JSON_DEPTH};

/// How far into a body the kernel has to read before a unit can open.
///
/// The unit opens when the deepest declared pointer has resolved or the declared length ends. No
/// pointer is ever evaluated over a truncated prefix, which is the whole reason this is a value
/// the pump can compare rather than a rule someone remembers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeepestPointer {
    /// Nothing needs the body.
    None,
    /// A byte offset the scanner reached.
    Offset(usize),
    /// The end of the body, whatever that turns out to be.
    EndOfBody,
}
