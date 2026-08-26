// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INVOKE IR — the `Operation::INVOKE` subclass of the parent [`crate::ir::variant::IrReq`]
//! / [`crate::ir::variant::IrResp`] enums.
//!
//! Named `ToolCall` through 1.5. `Invoke` is the same shape — a caller names a target, hands it
//! arguments, and gets content or an error back — under a name that does not belong to one protocol:
//! it carries A2A `message/send` and MCP `completion/complete` alongside MCP `tools/call`, and an
//! MCP-flavoured name would be a protocol branch waiting to happen at every site that reads it.
//!
//! ## WHY THIS IS AN OPERATION AND NOT A PLANE
//!
//! MCP was first built as a parallel ingress path BESIDE the pipeline: 13,069 implementation lines
//! under `mcp/`, with **zero** `ProtocolReader`/`ProtocolWriter` implementations and **zero**
//! occurrences of `IrBlock`. Every concern the core already owned — the guarded fetch, the ingress
//! admission, the outbound credential, the hash-chained audit, the config section container — was
//! written a second time inside that directory, which is what `structure-lint`'s plane ledger has
//! been counting.
//!
//! The corrective is not a better plane. It is to stop having one: a tool call is an OPERATION, in
//! the same sense that a chat completion, an embedding and a transcription are operations, and it
//! reaches the same operation-blind middle through the same `protocol × operation` codec matrix.
//! Governance, budgets, audit, metrics, the breaker and failover then apply to it because it is in
//! the matrix, not because someone re-wired each of them into a second directory.
//!
//! ## WHAT A TOOL CALL IS, REDUCED TO ITS INVARIANTS
//!
//! A caller names a tool, hands it arguments, and gets content back or an error. That is the whole
//! operation. It has no messages, no system prompt, no sampling controls — which is exactly why
//! `IrRequest` (the CHAT subclass) could never have carried it, and why the parent enum earns its
//! keep here rather than being a formality.
//!
//! ## THE TWO ERROR CHANNELS ARE NOT THE SAME CHANNEL
//!
//! This is the distinction the first implementation got wrong, and it is worth stating in the type
//! rather than in prose. A tool that RAN and FAILED is a successful call whose result carries
//! [`InvokeResp::is_error`] — the transport succeeded, the protocol succeeded, the tool did not.
//! A call that could not be made at all is a refusal and never reaches this type. Collapsing the
//! two tells a caller their request was malformed when their tool merely returned an error, and it
//! is also what makes an upstream failure indistinguishable from a policy refusal to the breaker.

// THE PURE DATA (`InvokeReq`/`InvokeResp`) RELOCATED to `busbar-substrate` (the neutral cross-plane
// IR leaf a plane crate names directly), and at Batch C-2 the family-blind `IrFacts` projection over
// `InvokeReq` travelled with it (the trait is now substrate-resident, so the impl must sit beside the
// trait or the type to satisfy the orphan rule). Core re-exports the data type from this historical
// path; the projection reaches every in-core caller through the same re-export.
pub use busbar_substrate::ir::invoke::{InvokeReq, InvokeResp};
