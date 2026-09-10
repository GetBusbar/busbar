// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `oauth_as:` SECTION'S GRAMMAR, and nothing else.
//!
//! ## What used to be here, and where it went
//!
//! This module was busbar's OAuth 2.1 authorization server: the seven routes, the `oauth-as`
//! service, the consent screen, the Client ID Metadata Document fetch, the ES256 signer, the
//! registration ceiling and the in-process store. All of it is now
//! `busbar-control-tokenmint`, a CONTROL-kind crate whose only busbar edge is `busbar-contract`,
//! mounted by a registry row the composition root owns (`busbar::root::control_tokenmint`) exactly
//! as the a2a / mcp / voice plane rows join. Core carries no route, no handler and no key for it,
//! and `busbar_core::state::App` has no field for it: a hard-wired
//! `crate::oauth_as::routes::mount(router, …)` line in the data router was the thing that made this
//! a core surface, and that line is gone.
//!
//! ## What stayed, and why
//!
//! The GRAMMAR of the `oauth_as:` block — [`config::OauthAsCfg`], its boot refusals, and the
//! validated [`config::AsIdentity`] the refusals produce. It stays for one reason that is not
//! inertia: `config_validate::secret_refs` walks `RootCfg` and MUST be able to SEE the operator's
//! `signing_key:` reference, because a secret the walker cannot reach is a secret nothing checks,
//! and that walker's whole design is that an omission is a compile error rather than an oversight.
//! The derived identity crosses to the crate through the substrate's nameless
//! `BuildCtx::resolved_section` slot, and the secret it named crosses ALREADY RESOLVED through
//! `BuildCtx::resolved_secret` — so the one place that reads operator secrets is still the config
//! layer, and the crate that signs with the material cannot reach a second secret.
//!
//! Moving this half out is the next step, and it is a step with a shape: the row declares
//! `parse_section` and `config_validate`, the crate's own `Section` becomes the parse target, and
//! this module goes with it. See `docs/design/control-tokenmint-rebuild.md`.

pub mod config;
