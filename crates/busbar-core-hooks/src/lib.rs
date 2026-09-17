// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `busbar-core-hooks` — the HOOK-DISPATCH home carved out of `busbar-core` (DECISIONS #19/#20).
//!
//! # What this crate is for
//!
//! 1.6.0 DELETES `busbar-core`: it dissolves into [`busbar-kernel`](../busbar_kernel) (the teller
//! loop), the `busbar-unit-*` step crates, and three `core`-kind sibling homes —
//! `busbar-core-config` (config + secret resolver), this crate (hook dispatch), and `busbar-oauth2`
//! (the `oauth_as:` plane, already landed). See `docs/design/ENGINE-KERNEL-DRAIN.md`.
//!
//! # `hooks` here is the CALLER, not the plugin kind
//!
//! This crate is the neutral caller that RUNS hooks — the thing `busbar-core::hooks` dispatches. It
//! is NOT the `hook` plugin kind: a hook plugin is `busbar-hook-<name>` and implements the hook ABI.
//! The distinction is a reviewed accepted-name entry in `xtask/src/gates/kind_isolation.rs`.
//!
//! # Wave-0 scaffold — dormant on purpose
//!
//! This is the announced, empty HOME (see `qa/kind-isolation.toml` `[[announced]]`). No engine
//! source has been reconciled in yet. `busbar-core::hooks` still owns the live dispatch and its
//! `hooks::gate` couples to `busbar-core::session` and the boot path; that move waits behind the
//! session/kernel reconcile and the switch-over rather than a byte-affecting shim into the shipped
//! money crate.
//!
//! # The one-way rule (Cargo-enforced)
//!
//! This crate MUST NEVER name `busbar-core`: the home exists so `busbar-core` can eventually depend
//! on IT, and the reverse edge is the dependency cycle Cargo refuses. It is `core` kind on the same
//! neutral terms as `busbar-kernel` and `busbar-caps`, reaching only the neutral spine.
