// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE PLACE THIS CRATE NAMES THE PLUGIN LOADER (ARCHITECT 2026-09-29): every root file reaches
//! the loader through `crate::root::loader::…`, so the composition root's coupling to the plugin
//! tooling is this one line, not a name repeated at each use.

pub use busbar_plugin_loader::*;
