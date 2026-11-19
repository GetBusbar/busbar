// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`LateDirectory`]: the directory a `HostNeeds` is built over before the store it reads exists (the same reason
//! as `plugin_records::LateRecords`): every DIRECTORY Need answers `Unavailable` until the boot installs the one
//! directory, once, after the store opens and before the first 2c instance.

use std::sync::{Arc, OnceLock};

use busbar_plugin_abi::host_side::caller::Caller;
use busbar_plugin_abi::host_side::needs::{DirNeed, NeedErr, NeedOut};

use super::PluginDirectory;
