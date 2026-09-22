// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BUSBAR AS AN OAUTH 2.1 AUTHORIZATION SERVER (`oauth_as:`), off unless configured.
//!
//! ## 1.6.0: split into this config carrier and the sibling `busbar-oauth2` crate
//!
//! The plane's RUNTIME (`AsPlane`, its routes, the consent screen, the CIMD fetch, the DCR policy
//! ceiling, the AS's own ES256 signer) now lives in `busbar-oauth2`, a sibling crate that depends
//! on busbar-core ONE-WAY. This module keeps only [`config`] (`OauthAsCfg`/`AsIdentity`) and
//! [`seam`] (the small fn-pointer pair core's `router`/`appbuild` call through to reach the plane
//! without naming it).
//!
//! [`config`] stays here — not because the plane's code was hard to move, but because
//! `busbar-core`'s OWN `DeployConfig` and its validated twin embed `OauthAsCfg`/`AsIdentity` BY
//! VALUE for the single-document config pipeline (`config::prepass`'s `LiftableSection`,
//! `config::resolve`), and `config_validate::secret_refs` exhaustively destructures `AsIdentity`
//! (no `..`) to walk its one secret-bearing field. Moving those types to `busbar-oauth2` would need
//! core to name them back to parse and validate its own config — the exact reverse edge Cargo
//! refuses. See `busbar-oauth2`'s own crate doc for the plane half of this split.
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
//! table has nothing to describe. That is the same posture `mcp:` takes.
//!
//! It is CHECKED rather than asserted, and the check is `tests/mount_tests.rs`: it subtracts the
//! unconfigured route table from the configured one, requires the difference to be exactly the
//! plane's path inventory, and then requires the unconfigured table to contain none of it. The
//! second half is the claim; the first half is what stops the second half from passing because the
//! mount was deleted. What that leaves outside the type system is the linked bytes, which is a
//! measurement rather than a test — see the release notes.
//!
//! ## The three registration mechanisms: ALL THREE ON, NO TOGGLES
//!
//! The `2026-07-28` MCP revision lists three ways a client obtains a `client_id`, in the order a
//! client should prefer them: pre-registration, **Client ID Metadata Documents**, and **Dynamic
//! Client Registration** — the last of which it marks *deprecated, retained for backwards
//! compatibility*. The 1.6.0 ruling is that busbar serves ALL THREE whenever `oauth_as:` is
//! configured, with no per-mechanism switches — the decision a reviewer can find is the config
//! block itself, and what makes always-on self-registration safe is that registration confers no
//! authority (the [`policy`] ceiling):
//!
//! * **Pre-registration**: the host provisions a [`oauth_as::client::Client`] into the store
//!   directly ([`plane::AsServer::register_client`]).
//! * **DCR** ([`policy`]) because it is what the clients shipping today actually speak. Mounted
//!   UNCONDITIONALLY at `{issuer}/register`, and confined by a ceiling the registrant cannot move.
//! * **CIMD** ([`cimd`]) — the `SHOULD`. The seam is `Storage::get_client`: a `client_id` that
//!   parses as an HTTPS URL and is absent from the store is fetched, validated (`client_id` equal
//!   to the URL, `redirect_uris` taken from the document and exact-matched against the request by
//!   `oauth-as`) and materialised as an ephemeral [`oauth_as::client::Client`] under the SAME
//!   [`policy::default_grant_scopes`] ceiling registration uses. The document VALIDATION is
//!   busbar's own for now: `oauth-as` ships a CIMD validator behind an off-by-default `cimd`
//!   feature this tree does not enable — the handover is a marked TODO in [`cimd`] tied to
//!   `chore/1.6.0-oauth-as-0.9.3`, and it replaces one call, not the seam. That
//!   fetch is an SSRF surface by construction — the URL is attacker-supplied — and it goes through
//!   [`crate::net_guard`]'s resolve-then-pin guard rather than a second copy of it; a drifted copy
//!   of exactly that guard was a live cloud-metadata bypass on the MCP plane.
//!
//!   **It reaches for CORE, not for a plane.** An earlier draft of this note pointed at
//!   `a2a::fetch::fetch_card`, which would have made an authorization server's security control a
//!   dependency on the A2A plane's internals — and would have meant that deleting that plane broke
//!   the AS. The guard now lives in `net_guard` with the knobs as parameters, so this path supplies
//!   its OWN bounds — a client metadata document is a few kilobytes and the fetch is on an
//!   interactive authorization request, so 5 KB and 10 s, not the card fetch's 512 KB — and gets
//!   the same resolve-then-pin, the same unconditional cloud-metadata refusal and the same
//!   re-guarded redirect chain as every other guarded fetch in the tree.

// `pub`, not `pub(crate)`: `busbar-oauth2` (the sibling plane crate the rest of this module moved
// to) reaches `AsIdentity`/`OauthAsCfg`/`AsCfgError` and `AsIdentity::from_cfg` from outside this
// crate, and its own tests destructure `AsIdentity` exhaustively the same way
// `config_validate::secret_refs` does. Widened at the extraction's demand, not by design intent.
pub mod config;
pub mod seam;

// THE GATING PROOF and THE FLOW moved to `busbar-oauth2` with the plane they prove
// (`src/tests/mount_tests.rs` / `src/tests/flow_tests.rs`) — both need `AsPlane`/`routes::mount`
// directly, which core can no longer name. `config`'s own tests (`AsIdentity::from_cfg`, the
// secret-ref walk) stay colocated with `config` — wired from `config.rs` itself (`#[path =
// "tests/config_tests.rs"] mod config_tests;`), unchanged by this move.
