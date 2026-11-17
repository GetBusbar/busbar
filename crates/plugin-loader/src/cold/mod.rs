// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The crate's one sanctioned cold module (busbar-bad-patterns BP17): the refusal text and the
//! rare off-path work (load, config validation, admin listings) that the request-path modules
//! call out of line. It sits beside the marked modules, outside the request-path marker. Every fn
//! here is `#[cold]` or `#[inline(never)]`, holds no `while`/`loop`, and never sweeps request data
//! (a parameter) with a loop or an iterator. One submodule per request-path module it serves.

pub(crate) mod auth_axis;
pub(crate) mod auth_door;
pub(crate) mod dispatch;
pub(crate) mod durable_documents;
pub(crate) mod export_axis;
pub(crate) mod export_door;
pub(crate) mod ffi_thread;
pub(crate) mod highwater;
pub(crate) mod host;
pub(crate) mod observe;
pub(crate) mod rows;
pub(crate) mod secret_calls;
pub(crate) mod store_v4;
