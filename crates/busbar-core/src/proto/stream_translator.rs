// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The NEUTRAL streaming-translator seam that STAYS in busbar-core (G6 A4b). The concrete
//! `StreamTranslate` relocated to the `busbar-llm` plugin (`proto_stream.rs`); core holds only this
//! byte-in/byte-out trait and a fn-ptr factory the plugin installs, so core names ZERO concrete
//! stream IR. In core's test/`test-support` build the plugin's `proto_stream` is `#[path]`-netted
//! back as `crate::proto::stream`, so the factory routes there directly; in production it routes
//! through the installed pointer (the composition root installs it alongside `install_protocols`).

use std::sync::OnceLock;

// The neutral `StreamTranslator` trait RELOCATED DOWN to `busbar_substrate::proto` so the
// `busbar-llm` plugin's `StreamTranslate` implements it without reaching into `busbar-core`. Core
// keeps only the fn-ptr factory glue below; the trait is re-exported at `crate::proto::StreamTranslator`
// (see `proto/mod.rs`). By-identity relocation — behavior byte-identical.
use busbar_substrate::proto::StreamTranslator;

/// The plugin-provided factory that builds a concrete `StreamTranslate` for an ingress→egress pair.
/// Installed once by the composition root (production); the test build routes to the netted
/// `crate::proto::stream::new_stream_translator` directly and never reads this.
type StreamTranslatorFactory = fn(&str, &str, bool) -> Option<Box<dyn StreamTranslator>>;

static STREAM_TRANSLATOR_FACTORY: OnceLock<StreamTranslatorFactory> = OnceLock::new();

/// Install the plugin's streaming-translator factory. Idempotent-by-first-write (the composition root
/// registers once); a second install is ignored so a test harness cannot clobber a live pointer.
pub fn install_stream_translator_factory(f: StreamTranslatorFactory) {
    let _ = STREAM_TRANSLATOR_FACTORY.set(f);
}

/// The SINGLE streaming-translator construction seam both forward paths (`engine/mod.rs`,
/// `engine/walk.rs`) call. Neutral in and out. It routes to the installed pointer (returns `None` —
/// legacy raw passthrough — when no plugin installed one, e.g. a core-only build with no dialects).
///
/// Under core's OWN test binary (`cfg(test)`) it instead routes to the `busbar-llm` concrete factory
/// DIRECTLY — through a `tests/` fixture the neutral-purity lint excludes (`stream_factory_fixture`),
/// so no plugin symbol appears in neutral source and no runtime `install_*` call is needed before a
/// test that drives the seam standalone (the streaming-fidelity suites call it without booting an App).
/// This replaces the deleted `#[path]` witness (`super::stream::new_stream_translator`). External
/// `test-support` consumers (the plugin test binaries) have `cfg(test)` false and reach the installed
/// factory, which their own test setup fills through [`install_stream_translator_factory`].
#[cfg(test)]
pub fn new_stream_translator(
    ingress: &str,
    egress: &str,
    is_sse: bool,
) -> Option<Box<dyn StreamTranslator>> {
    super::stream_factory_fixture::new_stream_translator(ingress, egress, is_sse)
}

#[cfg(not(test))]
pub fn new_stream_translator(
    ingress: &str,
    egress: &str,
    is_sse: bool,
) -> Option<Box<dyn StreamTranslator>> {
    STREAM_TRANSLATOR_FACTORY
        .get()
        .and_then(|f| f(ingress, egress, is_sse))
}
