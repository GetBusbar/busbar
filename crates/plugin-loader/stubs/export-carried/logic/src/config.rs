// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `settings:` grammar of an `export.<name>.module: request-log-webhook` instance — config
//! grammar, tracked by the config-schema gate here, where the sink that reads it lives (K9c).

use serde::Deserialize;

/// `settings:` of an `export.<name>.module: request-log-webhook` instance — relocated from the retired
/// `observability` webhook keys. Also absorbs the retired `generic-webhook` exporter: its ONLY extra
/// over this one was `auth_header:`, which is now just a setting here, and its other reason to exist
/// (a SECOND webhook target) is what the named-instance map itself provides. The FIELD ORDER is the
/// order serde names them in an unknown-field refusal: do not reorder.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WebhookSettings {
    /// The webhook target URL — REQUIRED, `https://`-only, refused by the host's policy when it
    /// targets an internal host (relocated from the retired `observability.request_log_webhook_url`).
    pub url: String,
    /// An optional auth header applied to every delivery from THIS instance (e.g.
    /// `{ name: Authorization, value: "Bearer ${WEBHOOK_TOKEN}" }`). The `value` rides the config's
    /// `${VAR}` env interpolation, so a secret is never stored literally.
    #[serde(default)]
    pub auth_header: Option<ExportAuthHeader>,
    /// Max concurrent deliveries (default 64) — relocated from `max_inflight_webhook_deliveries`.
    #[serde(default = "default_max_inflight")]
    pub max_inflight_deliveries: usize,
    /// Per-delivery timeout (seconds, default 2) — relocated from `webhook_delivery_timeout_secs`.
    /// Applied PER INSTANCE (each sink carries its own deadline).
    #[serde(default = "default_timeout_secs")]
    pub delivery_timeout_secs: u64,
}

/// One `{ name, value }` auth header for a webhook export instance.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExportAuthHeader {
    pub name: String,
    pub value: String,
}

/// The default in-flight bound per instance.
pub const DEFAULT_MAX_INFLIGHT: usize = 64;
/// The default per-delivery deadline (seconds).
pub const DEFAULT_TIMEOUT_SECS: u64 = 2;

fn default_max_inflight() -> usize {
    DEFAULT_MAX_INFLIGHT
}

fn default_timeout_secs() -> u64 {
    DEFAULT_TIMEOUT_SECS
}
