// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SECRET: not wired yet.

use crate::{Config, Spec, Target};

pub(crate) fn specs(_cfg: &Config, _target: &Target) -> Result<Vec<Spec>, String> {
    Err("the secret workload is not wired yet".into())
}
