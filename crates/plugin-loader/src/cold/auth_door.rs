// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cold code of `crate::auth_door`.

use std::sync::Arc;

use busbar_contract::abi::mechanism::call::Blob;
use busbar_contract::plugin::KernelSeal;

use crate::auth_door::KeptSecrets;
use crate::dispatch::kinds::auth::Auth;
use crate::dispatch::Plugin;

/// Error: the auth plugin declined and said why; the instance notes it and the host logs it.
#[cold]
pub(crate) fn note_declined(plugin: &Plugin<Auth>, severity: u8, what: &str, reason: &str) {
    let line = format!("{what}: {reason}");
    plugin.note(severity, &line);
    // The reason is plugin text: the plain `text` field, never the message (IF §12.16). A routine
    // decline is per-request, so it is debug, not one INFO line per rejected credential.
    let text = reason;
    match severity {
        0 => tracing::debug!(plugin = %plugin.name(), text, "{what}"),
        _ => tracing::warn!(plugin = %plugin.name(), text, "{what}"),
    }
}

/// Boot: an auth instance's sink keeps its plugin name.
#[cold]
pub(crate) fn sink_plugin(plugin: &str) -> String {
    plugin.to_owned()
}

/// Boot: an auth instance lends its credentials once, when it opens or refreshes.
#[cold]
pub(crate) fn lent_blobs(
    secrets: &KeptSecrets,
    seal: &(dyn KernelSeal + Send + Sync),
) -> Vec<Blob> {
    secrets.lent(seal).collect()
}

/// Error: the auth instance returned invalid carrier metadata.
#[cold]
pub(crate) fn invalid_carriers() -> String {
    "auth instance returned invalid carrier metadata".to_owned()
}

/// Config: an open or refresh that names no carriers keeps the previous ones.
#[cold]
pub(crate) fn kept_carriers(previous: &[String]) -> Vec<String> {
    previous.to_vec()
}

/// Error: the auth instance's login presentation did not read.
#[cold]
pub(crate) fn presentation_refused(e: &str) -> String {
    e.to_owned()
}

/// Config: an instance's carriers are shared once per open or refresh.
#[cold]
pub(crate) fn shared_carriers(carriers: Vec<String>) -> Arc<[String]> {
    Arc::from(carriers)
}

/// Error: the instance's lifecycle generations ran out.
#[cold]
pub(crate) fn generation_exhausted() -> String {
    "auth lifecycle generation exhausted".to_owned()
}

/// Boot: an opened auth instance keeps its label.
#[cold]
pub(crate) fn instance_label(label: &str) -> String {
    label.to_owned()
}

/// Config: lists the instance's carriers for config and admin.
#[cold]
pub(crate) fn listed_carriers(carriers: &[String]) -> Vec<String> {
    carriers.to_vec()
}

/// Error: a second refresh found one already in flight.
#[cold]
pub(crate) fn refresh_in_flight(label: &str) -> String {
    format!("auth instance `{label}`: a refresh is already in flight")
}
