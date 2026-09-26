// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin SDK under the name a plugin built against an older busbar still spells.
//!
//! The SDK is [`busbar_contract::abi::sdk`] (DECISIONS #84 merged the SDK into the contract). Every
//! item a plugin reached as `busbar_plugin_sdk::X` — the export macros, the handler traits, the wire
//! types, the boundary — is that module's `X`, re-exported here unchanged, so a pinned plugin's
//! source builds as it always did and its artifact is the same artifact.

#![forbid(unsafe_code)]

pub use busbar_contract::abi::sdk::*;
