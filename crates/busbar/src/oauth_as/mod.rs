// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BUSBAR AS AN OAUTH 2.1 AUTHORIZATION SERVER (`oauth_as:`), off unless configured.
//!
//! ## What this plane is for
//!
//! busbar already speaks OAuth as a RESOURCE server: an operator points it at Okta, Entra or Auth0,
//! and busbar refuses any token not minted for its own canonical URI. That covers the deployment
//! that has an identity provider and can get a client registered in it.
//!
//! The clients people actually run cannot do that. Codex, ChatGPT and Claude.ai discover an MCP
//! server, register themselves, and expect a token — and an enterprise identity team will not turn
//! on RFC 7591 dynamic registration to let them. So a gateway whose only OAuth answer is "point at
//! your IdP" cannot connect the agents its users already have. This plane closes that: with
//! `oauth_as:` configured, busbar IS the authorization server, and an agent that has never heard of
//! this deployment completes a login against it with nothing configured on either side.
//!
//! ## It costs nothing when it is off, and that is a property rather than an aspiration
//!
//! `oauth-as` is a NORMAL dependency, so the shipped binary can always serve this plane and an
//! operator never meets a config block the binary in front of them cannot honour. What "off" means
//! is that [`crate::state::App::oauth_as`] is `None`: no [`oauth_as::server::AuthorizationServer`]
//! is constructed, no store is allocated, no signing key is generated or read, no sweeper task is
//! spawned, and no route is mounted — so the auth middleware has nothing to consult and the route
//! table has nothing to describe. That is the same posture `mcp:` takes, and it is measured rather
//! than asserted: see `tests/zero_cost_tests.rs` and the idle-RSS figures in the release notes.
//!
//! ## The three registration mechanisms, and why busbar serves two of them
//!
//! The `2026-07-28` MCP revision lists three ways a client obtains a `client_id`, in the order a
//! client should prefer them: pre-registration, **Client ID Metadata Documents**, and **Dynamic
//! Client Registration** — the last of which it marks *deprecated, retained for backwards
//! compatibility*. busbar serves both of the two that need a server:
//!
//! * **DCR** ([`policy`]) because it is what the clients shipping today actually speak. IMPLEMENTED
//!   HERE, off by default, and confined by a ceiling the registrant cannot move.
//! * **CIMD** — the `SHOULD`, and **NOT IMPLEMENTED IN THIS CHANGE**. Said here rather than left to
//!   be discovered, because a plane that serves the deprecated mechanism and not its replacement is
//!   a gap somebody has to know about. `oauth-as` 0.9.0 has no CIMD support and no client-resolution
//!   hook, so the seam is `Storage::get_client`: a `client_id` that parses as an HTTPS URL and is
//!   absent from the store is fetched, validated (`client_id` equal to the URL, `redirect_uris`
//!   matched against the request) and materialised as an ephemeral [`oauth_as::client::Client`]
//!   under the SAME [`policy::default_grant_scopes`] ceiling registration uses. That fetch is an
//!   SSRF surface by construction — the URL is attacker-supplied — and it must go through
//!   `a2a::fetch::fetch_card`'s resolve-then-pin guard rather than a second copy of it; a drifted
//!   copy of exactly that guard was a live cloud-metadata bypass on the MCP plane.

pub(crate) mod config;
pub(crate) mod consent;
pub(crate) mod plane;
pub(crate) mod policy;
pub(crate) mod routes;
pub(crate) mod signer;
