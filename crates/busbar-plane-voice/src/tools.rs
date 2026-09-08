// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SERVER-SIDE TOOL EXECUTOR PORT (the tool-moat section of `plane4-duplex-session.md`).
//!
//! The whole reason a governed plane beats a dumb WS pipe: tool calls execute SERVER-SIDE, under
//! governance, and the browser is never trusted to author them. The runtime correlates a call by its
//! [`busbar_voice_codec::ir::tool::CallRef`], accumulates the streamed argument bytes, and on close hands the
//! `(name, arguments)` to this port for execution — never to the client. The port is plane-local and
//! dependency-inverted so the composition root binds the real tool registry while tests bind a fake.

use async_trait::async_trait;

/// EXECUTES ONE correlated tool call server-side and returns its opaque output payload — the bytes the
/// runtime frames back upstream as a `function_call_output`. `Send + Sync` so it is shared across the
/// concurrent per-frame handlers.
#[async_trait]
pub trait ToolExecutor: Send + Sync {
    /// Whether THIS NODE is the one that answers `name`.
    ///
    /// The two halves of the tool loop divide here. `true` — the default, and every executor's
    /// answer until one says otherwise — is the moat above: the runtime accumulates the arguments and
    /// calls [`Self::execute`], and the client never authors the result. `false` says the answer can
    /// only come from the client, which makes the call's reply leg a governed WAIT held by the node's
    /// own table ([`crate::governed::GovernedCalls`]) rather than an execution held here.
    ///
    /// Defaulted to `true` deliberately: an executor that has not thought about the question serves
    /// what it is asked, which is the safe end. The unsafe end would be a node that quietly stopped
    /// running its own tools and waited on a client that was never going to answer.
    fn serves(&self, _name: &str) -> bool {
        true
    }

    /// Run the tool named `name` with the accumulated `arguments` (opaque JSON bytes) and return the
    /// opaque result payload. An executor that does not recognize `name` returns an error-shaped
    /// payload rather than panicking — the session survives one bad tool call.
    async fn execute(&self, name: &str, arguments: &[u8]) -> Vec<u8>;
}

/// A TEST/DEV executor that echoes the call back as a JSON object — enough to prove correlation
/// (the right `name` + `arguments` reached the right call) without a real tool registry.
#[derive(Debug, Default, Clone, Copy)]
pub struct EchoToolExecutor;

#[async_trait]
impl ToolExecutor for EchoToolExecutor {
    async fn execute(&self, name: &str, arguments: &[u8]) -> Vec<u8> {
        // The SERIALIZER decides what a string may contain, not this call site. `name` arrives off
        // the provider's JSON with no charset restriction, and spliced into a hand-written object it
        // only had to contain a quote to write attacker-chosen KEYS into the echoed result — from a
        // `pub` module of a production crate, however plainly this type is documented as test/dev.
        // Arguments that are not JSON travel as the string they are, rather than as a fragment
        // pasted where a value belongs.
        let echo = serde_json::from_slice::<serde_json::Value>(arguments).unwrap_or_else(|_| {
            serde_json::Value::String(String::from_utf8_lossy(arguments).into_owned())
        });
        // An object of a string and an already-parsed value has no unrepresentable shape; the
        // fallback keeps the signature total rather than making a test double a panic site.
        serde_json::to_vec(&serde_json::json!({ "tool": name, "echo": echo })).unwrap_or_default()
    }
}
