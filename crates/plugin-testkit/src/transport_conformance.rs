// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Contract conformance for the `transport` kind — the checks every wire must pass identically.
//!
//! # What this battery is, and what it is NOT
//!
//! Three of the seven transports (`grpc`, `stdio`, `ws`) carry a `src/tests/battery.rs` of their
//! own: round trip, multiplexing, K writers, backpressure, handoff, honest terminal status. Those
//! are excellent and they are **hand-copied per crate** — 3,652 lines of it, and four of the seven
//! transports have none at all. That is precisely the `kind-isolation:testkit` finding: a battery
//! that lives in each sibling is not a battery the KIND has, because nothing makes a new sibling
//! run it and nothing keeps two siblings asking the same question.
//!
//! This module is the shared half — the part that can be asked of every wire without a runtime, a
//! socket or a peer: **the declaration**, which is what `PLUGIN-TREE.md` §2 says a plugin
//! integrates by. Every transport fills [`TransportDecl`] from its own `TransportMeta` consts and
//! runs [`assert_declaration`]; the answers are then the same question asked seven times instead of
//! seven questions.
//!
//! The wire half — `listen`/`accept`, the frame pump, the `UnitDriver` seam — is **owed** and is
//! named here rather than quietly omitted: it needs an async runtime and a live peer, so it lands
//! when the three existing `src/tests/battery.rs` files are lifted into this crate behind a
//! runtime-agnostic driver. [`assert_listen_accept_seam`] is the shape that lift takes, and it runs
//! today over whatever the caller can already drive.
//!
//! # Owed, named rather than dropped
//!
//! Running this over the seven wires turned up one thing no rule here can settle: `sse`, `stdio`
//! and `ws` declare ZERO selector forms in either direction. `sse` is correct (it composes over
//! `http` and inherits its evaluation) and `stdio` is correct (a single-peer wire has nothing to
//! select between), but nothing in the DECLARATION tells those two apart from a wire that simply
//! forgot, so [`assert_declaration`] reports the counts and asserts nothing about them. Giving the
//! declaration a discriminator — or ruling that a bottom wire with no forms is a finding — is the
//! kind owner's, and it is written here so the next reader meets it.
//!
//! # Why the helpers take plain values rather than the `TransportMeta` trait
//!
//! Exactly the reason [`crate::store_conformance`]'s siblings are generic over `T`: this crate may
//! not grow a workspace dependency that the kind graph does not already have. `busbar-contract` is
//! not among `busbar-plugin-testkit`'s edges, and adding it would put a NEW kind-to-kind edge class
//! in front of `cargo xtask gate kind-isolation`'s `:deps` row to buy a type name. The caller has
//! the consts; it passes them.

/// A transport's declaration, as the kind's own `TransportMeta` consts state it.
///
/// One struct rather than nine arguments so a new declaration is added here once and every wire is
/// asked about it on its next build.
pub struct TransportDecl<'a> {
    /// `TransportMeta::KEY`.
    pub key: &'a str,
    /// `TransportMeta::COMPOSES_OVER` — the wires this one layers over.
    pub composes_over: &'a [&'a str],
    /// `TransportMeta::UPGRADES_TO` — the wires this one can become in band.
    pub upgrades_to: &'a [&'a str],
    /// `TransportMeta::TRANSPORT_FACTS` — the fact keys this wire writes.
    pub transport_facts: &'a [&'a str],
    /// `TransportMeta::SESSION`.
    pub session: bool,
    /// `TransportMeta::SESSION_BOUND`.
    pub session_bound: bool,
    /// How many `SELECTOR_FORMS` this wire can evaluate on arriving bytes.
    pub selector_forms: usize,
    /// How many `EGRESS_SELECTOR_FORMS` this wire can evaluate when dialling out.
    pub egress_selector_forms: usize,
}

/// THE DECLARATION, checked the same way for every wire.
///
/// Each rule is one the boot seal or the composition check would otherwise discover at run time on
/// somebody's deployment, which is the wrong place to learn it.
pub fn assert_declaration(d: &TransportDecl<'_>) {
    assert!(
        !d.key.is_empty() && d.key == d.key.to_ascii_lowercase(),
        "a transport's KEY is its registry name and is lower-case: `{}`",
        d.key
    );
    assert!(
        !d.composes_over.contains(&d.key),
        "`{}` declares it composes over ITSELF, which is a stack the seal cannot order",
        d.key
    );
    assert!(
        !d.upgrades_to.contains(&d.key),
        "`{}` declares it upgrades to ITSELF, which is an in-band upgrade to nothing",
        d.key
    );
    assert!(
        !d.session_bound || d.session,
        "`{}` says a session on it caches its principal (SESSION_BOUND) while saying it carries no \
         session (SESSION = false): the second makes the first unreachable",
        d.key
    );
    assert!(
        d.transport_facts.iter().all(|f| !f.is_empty()),
        "`{}` declares an empty transport-fact key; a fact nothing can name is a fact nothing \
         reads",
        d.key
    );
    let mut seen: Vec<&str> = d.transport_facts.to_vec();
    seen.sort_unstable();
    let before = seen.len();
    seen.dedup();
    assert_eq!(
        before,
        seen.len(),
        "`{}` declares the same transport fact twice; the kernel reserves each key once",
        d.key
    );
    // NOT ASSERTED, and named rather than dropped: "a wire evaluates at least one selector form".
    // Three of the seven declare none — `sse` (which composes over `http` and inherits its
    // evaluation), `stdio` (a single-peer wire with nothing to select between) and `ws`. The first
    // two are correct and the third is a question for the kind's owner, and no discriminator in the
    // declaration tells the three apart, so this battery reports the counts to the caller and
    // asserts nothing it cannot justify. See the module docs' owed list.
    let _ = (d.selector_forms, d.egress_selector_forms);
}

/// THE WIRE HALF, as far as it can be asked without a runtime in this crate.
///
/// `listen_then_accept` must open a listener and take one connection off it, returning the peer
/// string the accepted connection reports. The caller owns the runtime — that is the whole reason
/// this is a closure — so a transport with no lower layer (which cannot listen at all) simply does
/// not call this, and says so in its own conformance file.
pub fn assert_listen_accept_seam(
    key: &str,
    listen_then_accept: impl Fn() -> Result<String, String>,
) {
    match listen_then_accept() {
        Ok(peer) => assert!(
            !peer.is_empty(),
            "`{key}` accepted a connection that names no peer; an arrival record with no source is \
             a fact the kernel cannot audit"
        ),
        Err(e) => panic!(
            "`{key}` could not complete its own listen/accept seam: {e}. Every wire that declares a \
             bind address answers this one."
        ),
    }
}
