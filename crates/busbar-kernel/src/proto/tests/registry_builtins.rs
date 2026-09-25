// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CORE'S OWN TEST-BINARY BUILT-IN PROTOCOL LIST — the neutral synthetic set
//! (`neutral_protocols.rs`, beside this file). The kernel's test binary names no plane crate: a plugin's
//! real declarations are tested by the plugin. The list is fixed-order, so `known_protocols()`'s
//! order (the metric-family index and the config-error `must be one of:` order) is stable, and
//! allocation-free to read, which the registry's memoized fast path relies on.

use busbar_kernel::proto::registry::ProtocolDecl;

#[path = "neutral_protocols.rs"]
mod neutral_protocols;

/// The kernel test binary's protocol set — see the module header.
pub fn test_builtin_decls() -> &'static [&'static ProtocolDecl] {
    neutral_protocols::NEUTRAL_PROTOCOLS
}
