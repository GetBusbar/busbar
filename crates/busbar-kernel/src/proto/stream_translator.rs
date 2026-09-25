// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The NEUTRAL streaming-translator seam that STAYS in busbar-core (G6 A4b). The concrete
//! `StreamTranslate` relocated to the extracted dialect plugin crate (`proto_stream.rs`); core holds
//! only this byte-in/byte-out trait and a fn-ptr factory the plugin installs, so core names ZERO
//! concrete stream IR. In every build the seam routes through the installed pointer (the
//! composition root installs it alongside `install_protocols`).

// The neutral `StreamTranslator` trait AND the fn-ptr factory (the `OnceLock`, its installer, and the
// production construction seam) RELOCATED DOWN to `busbar_kernel::proto` so the dialect plugin
// installs and drives them through the neutral ABI without reaching into `busbar-core`. The trait is
// re-exported at `crate::proto::StreamTranslator` (see `proto/mod.rs`); the installer and the seam are
// re-exported below, in EVERY build.

// The installer is neutral in every build — the composition root (production) and the plugin test
// setup both register their factory through the substrate `OnceLock`.
pub use busbar_kernel::proto::install_stream_translator_factory;

/// The SINGLE streaming-translator construction seam the forward paths call. Neutral in and out: it
/// routes to the installed pointer (returns `None` — legacy raw passthrough — when no plugin installed
/// one).
///
/// It is the SAME seam in core's own test binary. That binary used to route it straight to the
/// dialect plugin's concrete factory through a `tests/stream_factory_fixture.rs` that named the plugin
/// crate; nothing in this crate calls the seam (the forward paths that do live in the plane crates,
/// which link this crate as a normal, non-test dependency and always got this re-export), so the
/// routing arm and its fixture are gone and the test binary names no plugin to build a translator.
pub use busbar_kernel::proto::new_stream_translator;
