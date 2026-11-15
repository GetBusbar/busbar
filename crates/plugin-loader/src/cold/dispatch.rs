// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The cold code of `crate::dispatch`, one submodule per group of dispatch modules.

pub(crate) mod load;
pub(crate) mod runtime;
pub(crate) mod services;
