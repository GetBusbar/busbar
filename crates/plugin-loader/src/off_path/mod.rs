// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The request-path modules' code that runs off the request path: once per load, open, config
//! reload or secret rotation, never per request (the engine lead's Q4 ruling: each move shows every
//! caller). It sits beside the marked modules, outside the request-path marker. One submodule per
//! request-path module it serves.

pub(crate) mod auth_door;
