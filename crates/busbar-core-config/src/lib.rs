// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `busbar-core-config` — the CONFIG + secret-resolver home carved out of `busbar-core`
//! (DECISIONS #19/#20).
//!
//! # What this crate is for
//!
//! 1.6.0 DELETES `busbar-core`: it dissolves into [`busbar-kernel`](../busbar_kernel) (the teller
//! loop), the `busbar-unit-*` step crates, and three `core`-kind sibling homes — this crate, the
//! config + secret-resolver home; `busbar-core-hooks`, the hook-dispatch home; and `busbar-oauth2`,
//! the `oauth_as:` plane (already landed). See `docs/design/ENGINE-KERNEL-DRAIN.md`.
//!
//! # Wave-0 scaffold — dormant on purpose
//!
//! This is the announced, empty HOME (see `qa/kind-isolation.toml` `[[announced]]`). No engine
//! source has been reconciled in yet. The L0 secret-resolver move
//! (`busbar-core::config::secret::{SecretResolver, resolve_settings}`) is **STOP-and-reported** for
//! this pass, not landed, because it cannot be made byte-safe against the shipped money path:
//!
//! * `resolve_settings`, `resolve`, `resolve_string`, `classify_setting`, `PluginResolveFn` and
//!   `SETTING_LITERAL_KEY` are all `pub(crate)` in `busbar-core::config::secret`, called directly
//!   by `busbar-core`'s own boot path (`auth::run_admin_chain`, `preflight`, `tls`, `state`,
//!   `appbuild`). A re-export shim across a crate boundary cannot preserve `pub(crate)` visibility,
//!   so the move would WIDEN the shipped money crate's secret surface to `pub` — a structural change
//!   to the live billed path, reserved for the serial switch-over, not a blind-swarm additive lane.
//!
//! # The one-way rule (Cargo-enforced)
//!
//! This crate MUST NEVER name `busbar-core`. The whole point of the home is that `busbar-core` will
//! eventually depend on IT (a re-export shim so its call sites stay unbroken); the reverse edge is
//! the dependency cycle Cargo refuses outright. It is `core` kind on the same neutral terms as
//! `busbar-kernel` and `busbar-caps`: it reaches only the neutral spine (api/caps/grammar/kernel/
//! substrate/timing) and carries no plane, dialect, transport or unit.
//!
//! # Landed: `parse` (config neutral-half wave, DECISIONS #5/#19)
//!
//! [`parse`] — the neutral boot/validate-time config-parsing helpers (`parse_duration_secs`
//! re-exported from `busbar_substrate::duration`, and the single `max_admin_scope:` ceiling-token
//! check `parse_ceiling`) — is the first config helper reconciled in. It names ONLY the neutral
//! spine (`busbar_substrate::{duration, config::auth}`, `busbar_contract::authz`), never the plane
//! or oauth config-by-value, so it moves as a byte-identical `git mv`. `busbar-core` re-exports it
//! at its historical `busbar_core::config::parse` path, so every call site is unchanged. The rest
//! of the config neutral half (migrate/overlay/named_map/prepass) stays in `busbar-core` this pass:
//! each still names the plane registry, `oauth_as::config`, `crate::export`, the `DeployCfg`
//! neighbourhood, or a core-local emit macro — the reverse edge Cargo refuses.

pub mod parse;
