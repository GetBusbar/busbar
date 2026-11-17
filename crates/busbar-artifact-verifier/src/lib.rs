// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Read-only artifact verification. Publisher trust does not qualify a cryptographic provider.
#![forbid(unsafe_code)]
pub mod refusal;
pub mod release_trust;
pub mod scan;
pub mod sign;
pub mod tarball;
pub mod verification;
use busbar_plugin_abi::types::KindCode;
/// The existing source-current rebuild remedy.
pub const REBUILD: &str = "rebuild the plugin against the 1.6.0 SDK";

/// The manifest word for a kind (`sign::KNOWN_KINDS`).
pub fn kind_word(kind: KindCode) -> &'static str {
    match kind {
        KindCode::Store => "store",
        KindCode::Secret => "secret",
        KindCode::Auth => "auth",
        KindCode::Hook => "hook",
        KindCode::Export => "export",
        KindCode::Plane => "plane",
        KindCode::Transport => "transport",
    }
}

/// The ONE abi_version this binary loads for `kind` (LINT-RULES R21: exact match, never a range
/// or a set); `None` for a kind it does not know.
pub fn supported_abi(kind: &str) -> Option<u32> {
    match kind {
        "store" => Some(busbar_artifact_metadata::versions::STORE.raw()),
        "secret" => Some(busbar_artifact_metadata::versions::SECRET.raw()),
        "auth" => Some(busbar_artifact_metadata::versions::AUTH.raw()),
        "hook" => Some(busbar_artifact_metadata::versions::HOOK.raw()),
        "export" => Some(busbar_artifact_metadata::versions::EXPORT.raw()),
        "plane" => Some(busbar_artifact_metadata::versions::PLANE.raw()),
        "transport" => Some(busbar_artifact_metadata::versions::TRANSPORT.raw()),
        _ => None,
    }
}
