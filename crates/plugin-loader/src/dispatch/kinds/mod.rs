// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SEVEN KINDS, as the dispatcher binds them: one [`super::Kind`] per `abi/<kind>/`, naming
//! its code, its table, its timeout outcome, each op's name, and the op's own `check_<op>` run on
//! every READY or FAILED answer. A kind's `check_<op>` is pure and lives beside its shapes in
//! `busbar-contract`; these adapters only read the op's `in`/`out` through [`super::Answer`], build
//! each slice a plugin-reported count names through `abi::mechanism::check::reported` (the count
//! checked against the host's cap first), and call the check; a kind's own fault is mapped to
//! the shared `Fault` the dispatcher logs where the kind does not answer it directly.

pub mod auth;
pub mod export;
pub mod hook;
pub mod plane;
pub mod secret;
pub mod store;
pub mod transport;
