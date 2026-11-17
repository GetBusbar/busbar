// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Read-only artifact metadata. No module opens or executes an image.
#![forbid(unsafe_code)]
pub mod civil;
pub mod extensions;
pub mod measurement;
pub mod observe;
pub mod plugin;
pub mod rendering;
pub mod rows;
pub mod settings_schema;
pub mod versions;
/// A public JSON blob's wire format.
pub const BLOB_JSON: u32 = 1;
