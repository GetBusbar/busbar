// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Error-type taxonomy strings aliased from their one canonical home,
//! `busbar_substrate::proto`, so every caller of the admin surface and every plugin's error
//! surface draw from the same vocabulary instead of each keeping its own copy. `main.rs`
//! references them via `crate::taxonomy::ERR_TYPE_*`.
//!
//! Relocated out of `admin::` (1.6.0 de-vocab): these are core's own INGRESS error-type tokens —
//! consumed by `ingress::dispatch`, `ingress::arrival_host`, and `router`, none of which are the
//! admin HTTP API — not admin-surface vocabulary. Byte-identical rename: only the Rust binding
//! path moves; the constant string VALUES (the wire error-type tokens) are unchanged.
//!
//! The admin API itself no longer has an error vocabulary of its own: every admin error — keys
//! included — is an [`crate::admin::v1::contract::AdminError`] projected by `key_err`/`err_json`
//! (design D route 2). The `internal_error`/`conflict_error`/`version_conflict_error` tokens that
//! used to be re-mapped onto the frozen `code` enum in a second place are gone with it.

pub(crate) const ERR_TYPE_NOT_FOUND: &str = busbar_substrate::proto::ERR_TYPE_NOT_FOUND;
pub(crate) const ERR_TYPE_INVALID_REQUEST: &str = busbar_substrate::proto::ERR_TYPE_INVALID_REQUEST;
