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
//!   answer rather than an opinion. Declared by the contract; what stays here is how specific one
//!   selector is against another, which is the within-a-plane precedence order and not part of
//!   what a selector IS.
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
    ArrivalLocation, Location, MaskKind, PathSeg as Segment, Selector, SelectorForm, SignedOver,
};

/// The closed JSON span grammar, named rather than spelled a second time.
///
/// The scanner is [`busbar_grammar`]'s, and the contract re-exports the same crate, so the pointer
/// a plane resolved and the pointer the pump resolves are resolved by one reading of one grammar.
pub use busbar_grammar::{resolve_pointer, scan_frontier, Resolved, Span, MAX_JSON_DEPTH};

/// The three axes the boot-time overlap check groups selector forms onto.
///
/// Deliberately coarser than the contract's per-form family: the overlap decision only needs to
/// know whether two selectors read the same axis at all, and every handshake-derived form is one
/// axis for that purpose. It is the kernel's own grouping, which is why it lives here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectorFamily {
    /// The request path.
    Path,
    /// A named header.
    Header,
    /// The transport handshake: server name, protocol, certificate subject, stream name, port.
    Transport,
}

/// Which axis a selector reads.
#[must_use]
pub fn family(selector: &Selector) -> SelectorFamily {
    match selector {
        Selector::ExactPath(_)
        | Selector::PrefixOneLevel(_)
        | Selector::PathPattern(_)
        | Selector::PathSuffix(_)
        | Selector::PathContains(_) => SelectorFamily::Path,
        Selector::HeaderExact(..) | Selector::HeaderPresent(_) | Selector::HeaderPrefix(..) => {
            SelectorFamily::Header
        }
        Selector::Sni(_)
        | Selector::ClientCertSubject(_)
        | Selector::StreamName(_)
        | Selector::Alpn(_)
        | Selector::Port(_) => SelectorFamily::Transport,
    }
}

/// How specific a selector is, for the within-one-plane precedence order: a literal beats a
/// variable, longer beats shorter, a whole path beats a fragment of one.
#[must_use]
pub fn specificity(selector: &Selector) -> u32 {
    match selector {
        Selector::ExactPath(p) => 10_000 + p.len() as u32,
        Selector::PathPattern(segments) => {
            let literals = segments
                .iter()
                .filter(|s| matches!(s, Segment::Lit(_)))
                .count() as u32;
            let open = segments
                .iter()
                .filter(|s| matches!(s, Segment::Tail))
                .count() as u32;
            5_000 + literals * 100 + segments.len() as u32 - open * 50
        }
        Selector::PrefixOneLevel(p) => 4_000 + p.len() as u32,
        Selector::HeaderExact(n, v) => 3_000 + (n.len() + v.len()) as u32,
        Selector::HeaderPrefix(n, v) => 2_000 + (n.len() + v.len()) as u32,
        Selector::HeaderPresent(n) => 1_500 + n.len() as u32,
        Selector::PathSuffix(s) | Selector::PathContains(s) => 1_000 + s.len() as u32,
        Selector::Sni(s) | Selector::ClientCertSubject(s) | Selector::StreamName(s) => {
            800 + s.len() as u32
        }
        Selector::Alpn(a) => 600 + a.len() as u32,
        Selector::Port(_) => 500,
    }
}

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
