// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-control-tokenmint — busbar as an OAuth 2.1 authorization server, as a CONTROL-kind crate
//!
//! ## What this crate is for
//!
//! busbar already speaks OAuth as a RESOURCE server: an operator points it at Okta, Entra or Auth0,
//! and busbar refuses any token not minted for its own canonical URI. That covers the deployment
//! that has an identity provider and can get a client registered in it. The clients people actually
//! run cannot do that: Codex, ChatGPT and Claude.ai discover an MCP server, register themselves,
//! and expect a token — and an enterprise identity team will not turn on RFC 7591 dynamic
//! registration to let them. With `oauth_as:` configured, busbar IS the authorization server, and
//! an agent that has never heard of this deployment completes a login against it.
//!
//! ## Why it is a CONTROL crate and not a plane
//!
//! A **data plane** is METERED and runs the full step list; a **control surface** is UNMETERED,
//! declares its routes as data, and runs the control path — verify, admit, audit, answer — and
//! nothing else. An authorization server is squarely the second. The consequences for review:
//!
//! * the route table is DATA ([`claims::ROUTES`]): seven rows, each a method, an admission bar, a
//!   handler and the path SEGMENTS as [`busbar_contract::grammar::PathSeg::Lit`], so a gate that
//!   never links this crate can read what it serves;
//! * every refusal the crate itself makes is ONE [`busbar_contract::error::PluginError`] under an
//!   `tokenmint.*` code, and the [`catalog`] beside the claims templates every one of them; what
//!   `oauth-as` answers on the wire is forwarded unchanged — the RFCs fix those bytes;
//! * the bodies ([`answer`]) are written over the `http` vocabulary and nothing else: no router,
//!   no extractor, no engine handle. The composition hands a request across and takes a response
//!   back; the manifest's only busbar edge is `busbar-contract`.
//!
//! ## It costs nothing when it is not configured
//!
//! The composition holds an `Option<`[`TokenIssuer`]`>`: `None` constructs no server, allocates
//! no store, generates or reads no signing key, spawns no sweeper and mounts no route.
//!
//! ## The three registration mechanisms: ALL THREE ON, NO TOGGLES
//!
//! Pre-registration ([`TokenIssuer::server`]), RFC 7591 DCR ([`policy`], confined by a ceiling
//! the registrant cannot move) and Client ID Metadata Documents ([`cimd`]) are on whenever the
//! crate is. The CIMD FETCH is not this crate's: the URL is attacker-supplied and the
//! resolve-then-pin guard that makes it safe belongs to the node, so the fetch is a seam
//! ([`CimdFetch`]) the composition fills with the node's guarded one.
//!
//! ## What is deliberately NOT durable, said here rather than discovered
//!
//! The store is `oauth_as::store::MemoryStorage`, in-process. Authorization codes, tokens, refresh
//! tokens and registered clients are lost on restart. Closing that means implementing
//! `oauth_as::store::Storage` over the contract's `Store` face, whose `take_*` methods have to be
//! the face's atomic `claim_key` or refresh tokens double-spend across nodes — recorded in
//! `docs/design/control-tokenmint-rebuild.md` as the seam still owed.

#![forbid(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod answer;
pub mod catalog;
pub mod cimd;
pub mod claims;
pub mod config;
pub mod consent;
pub mod policy;
pub mod signer;
pub mod surface;

pub use answer::{Request, Response};
pub use catalog::catalog;
pub use cimd::CimdFetch;
pub use config::{Identity, Section};
pub use surface::{spawn_sweeper, SweepFault, TokenIssuer};
