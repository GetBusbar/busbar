// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DECLARATION — this surface's identity, as associated constants and nothing else.
//!
//! Data only. Every value here is read by the composition that registers this crate and by the
//! gates that judge it; none of it is computed, none of it is configured, and none of it varies at
//! runtime. A kind's `*Meta` is the one place a reviewer can read what a crate claims to be without
//! reading what it does.

/// The registry key: the one word this surface is named by, in a log line, in a boot listing, and
/// in the control-surface seal. Lowercase and stable — the key is compared, not displayed.
pub const KEY: &str = "oauth2";

/// The DIALECT this control surface speaks. A control surface is a way of reaching busbar's
/// controls, and there is more than one grammar for doing that: the admin API speaks `admin`, and
/// this one speaks `oauth2`. Declared rather than inferred from the crate name, because the gate
/// that checks "one crate, one dialect" has to read a value rather than parse a path.
pub const DIALECT: &str = "oauth2";

/// The ABI generation this crate is written against.
///
/// **Owed, and named as owed rather than invented.** `busbar-contract` carries an ABI floor const
/// for exactly two kinds today (`STORE_ABI`, `TRANSPORT_ABI`); there is no `CONTROL_ABI` because
/// there is no `Kind::Control` yet — the control-kind row lands in `PLUGIN-TREE.md` and in
/// `kind-isolation` under a separate unit. When it does, this constant is replaced by a reference
/// to the contract's floor and `impl busbar_contract::plugin::Plugin for OAuth2Control` becomes
/// writable; until then a local `1` is the honest statement of "generation one, floor not yet
/// declared" and `src/tests/conformance.rs` records the gap as a test rather than as a comment.
pub const CONTROL_ABI: u16 = 1;

/// THE CONTROL PATH, in order — the whole of what a control surface is reachable at.
///
/// The contrast with a data plane is the point of the constant existing. A plane runs the metered
/// step list and is called at every one of its rungs; a control surface runs these four and is
/// called at no other. Nothing in this crate meters, prices, routes upstream or writes a plane
/// record, and this list is what a gate reads to check that.
pub const CONTROL_PATH: &[&str] = &["verify", "admit", "audit", "answer"];

/// The top-level `config.yaml` section whose mere EXISTENCE declares this surface. Absent ⇒ nothing
/// is built and nothing is mounted; see the crate header on what "off" costs.
pub const CONFIG_SECTION: &str = "oauth_as";
