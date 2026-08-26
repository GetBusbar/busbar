// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The RFC 9728 PROTECTED RESOURCE METADATA document.
//!
//! ## What this is for
//!
//! It is the second step of a discovery loop with exactly three steps, and it is the only step that
//! carries information the client could not have guessed:
//!
//! 1. The client posts to the MCP endpoint with no credential and gets `401` with
//!    `WWW-Authenticate: Bearer resource_metadata="<this document's URL>"`.
//! 2. It fetches this document and learns which authorization servers may mint tokens for this
//!    resource, and what this resource calls itself.
//! 3. It does ordinary OAuth against one of those authorization servers, asking for a token whose
//!    audience is the `resource` value below, and comes back.
//!
//! That is the whole of "an agent logs into busbar with no prior configuration". Nothing here is
//! busbar-specific; a client that has never heard of busbar completes it.
//!
//! ## Why it is unauthenticated, deliberately
//!
//! RFC 9728 §3 requires this document to be readable without credentials, and it must be: the entire
//! population of callers who need it are, by definition, the ones who do not have a token yet.
//! Requiring one would be a discovery loop that cannot be entered. It therefore declares
//! `RouteAuth::None` at its mount — the one exception on this plane, made explicitly at the route
//! rather than assumed by the handler.
//!
//! It discloses nothing that is not already public by construction: the deployment's own canonical
//! URI (which every client must know to obtain a token at all) and the operator's IdP issuer (which
//! every user of that IdP already knows). It does NOT enumerate tools, keys, pools or policy — the
//! catalogue is grant-scoped and lives behind the token.

// THE HANDLER IS NOT HERE ANY MORE, and its absence is the point of this file's remaining
// header. `GET /.well-known/oauth-protected-resource<mcp-path>` is served by
// `super::envelope::metadata_route` — the plane's neutral-seam handler — which reads the three
// deployment-specific facts off the host seam (`super::resource_of`) and frames them into the
// once-defined `busbar_substrate::ingress::protocol` document, beside the rest of this protocol's
// vocabulary.
//
// The plane-coherence ledger had verified, on 2026-08-11, that this document and the A2A plane's
// were the same document with the same audience rule. They were, and two copies of one document is
// two places for an audience to be spelled differently, which is the one defect this file's header
// says would make every correctly-behaved client in the world obtain a token this server refuses.

#[cfg(all(test, not(busbar_mcp_native)))]
#[path = "tests/resource_tests.rs"]
mod resource_tests;
