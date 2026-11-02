// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub use busbar_contract::{
    ArrivalLocation, Location, MaskKind, PathSeg as Segment, Selector, SelectorForm, SignedOver,
};

pub use busbar_contract::spans::{resolve_pointer, scan_frontier, Resolved, Span, MAX_JSON_DEPTH};

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

pub const SPECIFICITY_BAND: u32 = 1_000_000;

#[must_use]
pub fn specificity(selector: &Selector) -> u32 {
    let len = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
    let (class, within) = match selector {
        Selector::ExactPath(p) => (10, len(p.len())),
        Selector::PathPattern(segments) => {
            let literals = len(segments
                .iter()
                .filter(|s| matches!(s, Segment::Lit(_)))
                .count());
            let open = len(segments
                .iter()
                .filter(|s| matches!(s, Segment::Tail))
                .count());

            (
                9,
                literals
                    .saturating_mul(100)
                    .saturating_add(len(segments.len()))
                    .saturating_sub(open.saturating_mul(50)),
            )
        }
        Selector::PrefixOneLevel(p) => (8, len(p.len())),
        Selector::HeaderExact(n, v) => (7, len(n.len() + v.len())),
        Selector::HeaderPrefix(n, v) => (6, len(n.len() + v.len())),
        Selector::HeaderPresent(n) => (5, len(n.len())),
        Selector::PathSuffix(s) | Selector::PathContains(s) => (4, len(s.len())),
        Selector::Sni(s) | Selector::ClientCertSubject(s) | Selector::StreamName(s) => {
            (3, len(s.len()))
        }
        Selector::Alpn(a) => (2, len(a.len())),
        Selector::Port(_) => (1, 0),
    };
    class * SPECIFICITY_BAND + within.min(SPECIFICITY_BAND - 1)
}
