// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SERVER-SIDE TOOL EXECUTOR PORT (the tool-moat section of `BUSBAR-1.6.0.md` #18/#45).
//!
//! The whole reason a governed plane beats a dumb WS pipe: tool calls execute SERVER-SIDE, under
//! governance, and the browser is never trusted to author them. The runtime correlates a call by its
//! [`crate::codec::ir::tool::CallRef`], accumulates the streamed argument bytes, and on close hands the
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
    fn executes_here(&self, _name: &str) -> bool {
        true
    }

    /// Run the tool named `name` with the accumulated `arguments` (opaque JSON bytes) and return the
    /// opaque result payload. An executor that does not recognize `name` returns an error-shaped
    /// payload rather than panicking — the session survives one bad tool call.
    async fn execute(&self, name: &str, arguments: &[u8]) -> Vec<u8>;
}

/// THE DEFAULT: this node serves no tool. Every call the model makes is relayed to the caller, and
/// the caller's result is relayed back, exactly as the upstream realtime protocols define the loop.
/// The gateway never authors a tool's result.
#[derive(Debug, Default, Clone, Copy)]
pub struct ClientRelay;

#[async_trait]
impl ToolExecutor for ClientRelay {
    fn serves(&self, _name: &str) -> bool {
        false
    }

    async fn execute(&self, _name: &str, _arguments: &[u8]) -> Vec<u8> {
        Vec::new()
    }
}
