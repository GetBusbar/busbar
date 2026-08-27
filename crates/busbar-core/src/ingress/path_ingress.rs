// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PATH-MODEL ARRIVAL SIDE-REGISTRATION — a protocol-NAME-keyed table of the ingress a path-model
//! protocol serves itself, split OFF [`crate::proto::ProtocolDecl`] (Batch C-6).
//!
//! WHY IT IS NOT A DECL FIELD ANY MORE. `path_ingress` was a `ProtocolDecl` field whose type named
//! the core-only [`crate::ingress::dispatch::Arrival`] (which owns `Arc<App>`, `GovCtx`,
//! `CallerToken` — all deeply core-bound). When `ProtocolDecl` relocated DOWN to the neutral
//! `busbar_substrate::proto` leaf so an extracted protocol crate names it without reaching into
//! `busbar-core`, this one field could not travel: the substrate crate cannot name `Arrival`. Rather
//! than type-erase the arrival behind a neutral trait + a per-request downcast (not byte-identical,
//! and a compile-time guarantee traded for a runtime panic), the field is SPLIT OFF here into a
//! core-owned side-table keyed by the SAME protocol name the [`crate::proto::registry::Registry`]
//! uses. Same fn pointers, same `Box::pin` boxing, same per-request cost profile — a relocation, not
//! a behavior change.
//!
//! THE ONE READER is [`crate::ingress::dispatch::protocol_dispatch`], which consults
//! [`path_ingress_for`] by name exactly where it once read `decl_for(proto).path_ingress`.
//!
//! THE ONE WRITER is the composition root, through
//! [`crate::proto::registry::install_protocols_with_path_ingress`], which registers the decls and
//! these arrivals together and ASSERTS at boot that every `has_model_in_url` decl has an arrival —
//! so a registration drift is a LOUD PANIC at boot, not a silent fall-through to the body-model
//! branch (a wrong-behavior 404-shaped bug). The `busbar-core` `test`/`test-support` builds, which
//! compile the extracted dialects back in as built-ins (see `proto::registry::BUILTIN_DECLS`), fall
//! back to [`BUILTIN_PATH_INGRESS`] when no composition root installed — the exact mirror of the
//! built-in decl table, so the fixture registry the tests see matches a shipped binary's.

/// A path-model protocol's own ingress: one arrival in, one boxed response future out. `pub` so the
/// composition root and an extracted protocol crate (`busbar-llm`, which owns the two arrival fn
/// pointers via `busbar_core::ingress::{gemini_arrival, bedrock_arrival}`) can name the registration
/// pair type. It returns a BOXED future deliberately: the arms it replaced were `Box::pin`ed because
/// in a `match` every arm's future is inlined into the dispatch coroutine's union, so a ~5.7 KB arm
/// inflated the future every request carried regardless of dialect — a function pointer to a boxed
/// future keeps that cost on the requests that take it.
pub type PathIngress = fn(
    crate::ingress::dispatch::Arrival,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = axum::response::Response> + Send>,
>;

/// The arrivals the COMPOSITION ROOT installed, protocol-name-keyed. Set once by
/// [`install_path_ingress`]; consulted by [`path_ingress_for`]. A `Vec`, not a `&'static [_]`, for
/// the same reason [`crate::proto::registry`]'s `INSTALLED` is: the composition root ASSEMBLES it
/// from whichever protocol crates are linked.
static INSTALLED_PATH_INGRESS: std::sync::OnceLock<Vec<(&'static str, PathIngress)>> =
    std::sync::OnceLock::new();

/// THE BUILT-IN ARRIVALS — the fixture-surface mirror of `proto::registry::BUILTIN_DECLS`, present
/// ONLY in the builds that compile the extracted dialects back in (`test`/`test-support`). In the
/// production binary the composition root installs the crate's own arrivals through
/// [`install_path_ingress`], so this table does not exist and a build without a dialect resolves no
/// arrival for it — the deletion semantics the decl table has. The two arrival fns themselves live in
/// core (`crate::ingress::{gemini_arrival, bedrock_arrival}`), so this names them directly; only the
/// NAME→fn association is stated here, and only for the netted fixtures.
#[cfg(any(test, feature = "test-support"))]
static BUILTIN_PATH_INGRESS: &[(&str, PathIngress)] = &[
    (crate::proto::PROTO_GEMINI, super::gemini_arrival),
    (crate::proto::PROTO_BEDROCK, super::bedrock_arrival),
];

/// INSTALL THE PATH-MODEL ARRIVALS — the composition root's one write into this side-table, folded
/// into [`crate::proto::registry::install_protocols_with_path_ingress`] beside the decl install so
/// the two cannot drift. Set-once, mirroring `install_protocols`.
///
/// # Panics
/// - if called twice: two composition roots is a wiring bug, not a merge to attempt.
pub(crate) fn install_path_ingress(arrivals: Vec<(&'static str, PathIngress)>) {
    assert!(
        INSTALLED_PATH_INGRESS.set(arrivals).is_ok(),
        "install_path_ingress called twice: there is one composition root, and it registers once"
    );
}

/// RESOLVE A PATH-MODEL PROTOCOL'S ARRIVAL BY NAME — the by-name lookup `protocol_dispatch` performs
/// where it once read `decl_for(proto).and_then(|d| d.path_ingress)`. Consults the installed table
/// first (the shipped path), then the built-in fixtures (test/`test-support` only). `None` for a
/// body-model protocol, which is every protocol whose model is NOT in the URL — core then reaches the
/// universal ingress, exactly as before.
pub(crate) fn path_ingress_for(name: &str) -> Option<PathIngress> {
    if let Some(installed) = INSTALLED_PATH_INGRESS.get() {
        if let Some((_, f)) = installed.iter().find(|(n, _)| *n == name) {
            return Some(*f);
        }
    }
    #[cfg(any(test, feature = "test-support"))]
    if let Some((_, f)) = BUILTIN_PATH_INGRESS.iter().find(|(n, _)| *n == name) {
        return Some(*f);
    }
    None
}
