// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Off-path code for the request-path `auth` tree (built once per configuration, generation or
//! lifecycle). One submodule per slice of `auth`, so the slices that fill them do not collide.

pub(crate) mod chain;
pub(crate) mod keys;
pub(crate) mod login;
pub(crate) mod route_chain;
pub(crate) mod verdicts;
