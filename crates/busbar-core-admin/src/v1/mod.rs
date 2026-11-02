// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub mod contract;
pub mod json;
mod named_def_views;
pub mod service;

#[cfg(feature = "openapi-schema")]
pub mod schema;

#[cfg(test)]
#[path = "tests/hook_stage_projection.rs"]
mod hook_stage_projection;

#[cfg(test)]
#[path = "tests/read_view_redaction.rs"]
mod read_view_redaction;
