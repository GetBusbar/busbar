// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The NEUTRAL streaming-translator seam that STAYS in busbar-core (G6 A4b). The concrete
//! `StreamTranslate` relocated to the `busbar-llm` plugin (`proto_stream.rs`); core holds only this
//! byte-in/byte-out trait and a fn-ptr factory the plugin installs, so core names ZERO concrete
//! stream IR. In core's test/`test-support` build the plugin's `proto_stream` is `#[path]`-netted
//! back as `crate::proto::stream`, so the factory routes there directly; in production it routes
//! through the installed pointer (the composition root installs it alongside `install_protocols`).

// The neutral `StreamTranslator` trait AND the fn-ptr factory (the `OnceLock`, its installer, and the
// production construction seam) RELOCATED DOWN to `busbar_substrate::proto` so the `busbar-llm` plugin
// installs and drives them through the neutral ABI without reaching into `busbar-core`. The trait is
// re-exported at `crate::proto::StreamTranslator` (see `proto/mod.rs`); the installer is re-exported
// below in every build. What STAYS in core is only the `#[cfg(test)]` fixture-routing arm of the
// construction seam — core's OWN test binary routes straight to the netted `busbar-llm` concrete
// factory through a `tests/` fixture the neutral-purity lint excludes.
#[cfg(test)]
use busbar_substrate::proto::StreamTranslator;

// The installer is neutral in every build — the composition root (production) and the plugin test
// setup both register their factory through the substrate `OnceLock`.
pub use busbar_substrate::proto::install_stream_translator_factory;

/// The SINGLE streaming-translator construction seam both forward paths (`engine/mod.rs`,
/// `engine/walk.rs`) call. Neutral in and out.
///
/// Under core's OWN test binary (`cfg(test)`) it routes to the `busbar-llm` concrete factory DIRECTLY
/// — through a `tests/` fixture the neutral-purity lint excludes (`stream_factory_fixture`), so no
/// plugin symbol appears in neutral source and no runtime `install_*` call is needed before a test
/// that drives the seam standalone (the streaming-fidelity suites call it without booting an App).
/// This replaces the deleted `#[path]` witness (`super::stream::new_stream_translator`). In every
/// other build it re-exports the substrate production seam, which routes to the installed pointer
/// (returns `None` — legacy raw passthrough — when no plugin installed one).
#[cfg(test)]
pub fn new_stream_translator(
    ingress: &str,
    egress: &str,
    is_sse: bool,
) -> Option<Box<dyn StreamTranslator>> {
    super::stream_factory_fixture::new_stream_translator(ingress, egress, is_sse)
}

#[cfg(not(test))]
pub use busbar_substrate::proto::new_stream_translator;
