// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The NEUTRAL streaming-translator seam that STAYS in busbar-core (G6 A4b). The concrete
//! `StreamTranslate` relocated to the `busbar-llm` plugin (`proto_stream.rs`); core holds only this
//! byte-in/byte-out trait and a fn-ptr factory the plugin installs, so core names ZERO concrete
//! stream IR. In core's test/`test-support` build the plugin's `proto_stream` is `#[path]`-netted
//! back as `crate::proto::stream`, so the factory routes there directly; in production it routes
//! through the installed pointer (the composition root installs it alongside `install_protocols`).

use std::sync::OnceLock;

/// Neutral streaming byte-in/byte-out translator seam. The WHOLE [`StreamTranslate`] sits
/// behind this trait so emission ORDER is preserved verbatim — the streaming forward path
/// (`FirstByteBody`) holds an `Option<Box<dyn StreamTranslator>>` and never names the concrete
/// translator. `usage()` returns an OWNED [`crate::billing::TokenUsage`] (the billing consumers read
/// the four token totals, not the concrete `&IrUsage` borrow), so the seam names zero concrete IR;
/// the projection is billing-lossless. The other methods forward 1:1 to `StreamTranslate`'s inherent
/// methods, so behavior is byte-identical to the pre-trait direct calls.
pub trait StreamTranslator: Send {
    /// Feed a chunk of EGRESS bytes; return the translated INGRESS bytes for whatever COMPLETE frames
    /// are now available (empty if only a partial frame is buffered).
    fn feed(&mut self, chunk: &[u8]) -> Vec<u8>;
    /// Call once at end-of-stream; returns the INGRESS terminator plus any deferred terminal frames.
    fn finish(&mut self) -> Vec<u8>;
    /// The terminal token usage accumulated for this stream, projected to the neutral billing total,
    /// or `None` if no usage-bearing terminal event was seen. The streaming billing arm reads this
    /// for the per-request token fee.
    fn usage(&self) -> Option<crate::billing::TokenUsage>;
    /// The terminal stream ERROR message, or `None` for a clean stream — the breaker/billing gate.
    fn terminal_error(&self) -> Option<&str>;
    /// True once this translator abandoned its stream (reassembly overflow / malformed prelude).
    fn aborted(&self) -> bool;
    /// Record whether the ORIGINAL client request opted into streaming usage.
    fn set_client_include_usage(&mut self, include: bool);
}

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
/// `engine/walk.rs`) call. Neutral in and out. In the test build it routes to the netted concrete
/// factory; in production it routes to the installed pointer (returns `None` — legacy raw passthrough
/// — when no plugin installed one, e.g. a core-only build with no dialects).
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn new_stream_translator(
    ingress: &str,
    egress: &str,
    is_sse: bool,
) -> Option<Box<dyn StreamTranslator>> {
    super::stream::new_stream_translator(ingress, egress, is_sse)
}

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) fn new_stream_translator(
    ingress: &str,
    egress: &str,
    is_sse: bool,
) -> Option<Box<dyn StreamTranslator>> {
    STREAM_TRANSLATOR_FACTORY
        .get()
        .and_then(|f| f(ingress, egress, is_sse))
}
