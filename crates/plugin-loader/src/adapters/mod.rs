// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The adapters: one type per kind implementing its port over the kind's `Proxy` (IF §11.3). W0-ABI stub: the
//! adapter types only; L3-L9 fill them.

pub mod auth;
pub mod export;
pub mod hook;
pub mod plane;
pub mod secret;
pub mod store;
pub mod transport;
