// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core-owned mapping of admitted instances' actual CONFIG answers into the migration writer.

use super::Configured;
use busbar_plugin_loader::instance::{Described, Settled};

pub(super) fn answer(
    _index: u32,
    _instance: &Configured,
    _described: &Described,
    _settled: Settled,
) -> Result<busbar_migrate::Settled, String> {
    Err("CONFIG: settled answer not prepared".to_owned())
}
