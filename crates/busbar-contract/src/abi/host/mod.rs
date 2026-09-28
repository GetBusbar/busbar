// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST TABLES EVERY KIND SHARES: the services a host hands a plugin of any kind, lowered to
//! `#[repr(C)]`. The kernel never learns which kind or which instance is calling — the context a
//! table is handed with names the instance, and nothing else crosses.

pub mod conn;
pub mod service;
