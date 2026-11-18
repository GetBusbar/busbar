// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The request-path modules' code that runs off the request path: once per load, bind or
//! configuration, at dispatcher start or at a wedged worker's replacement, never per request (lint
//! ruling Q4: each move lists every caller of what it moves). It sits beside the marked modules,
//! outside the request-path marker, and the marked modules re-export the paths their callers use;
//! the request path only reads what it built. One submodule per request-path module it serves.
//!
//! Code holding `unsafe` stays in its pinned file (the unsafe register, unsafe.yaml: its interim
//! rows are never added or raised): a submodule here reads plugin memory through the safe
//! primitives its request-path module keeps, or is declared at its own path (`#[path]`). Every
//! submodule but the path-pinned `durable_documents` denies unsafe code.

#[deny(unsafe_code)]
pub(crate) mod auth_door;
#[deny(unsafe_code)]
pub(crate) mod conn_services;
// Kept at its path (the unsafe register, unsafe.yaml, pins its count per file).
#[path = "../durable_documents.rs"]
pub(crate) mod durable_documents;
#[deny(unsafe_code)]
pub(crate) mod export_bindings;
#[deny(unsafe_code)]
pub(crate) mod held;
#[deny(unsafe_code)]
pub(crate) mod kinds_export;
#[deny(unsafe_code)]
pub(crate) mod kinds_hook;
#[deny(unsafe_code)]
pub(crate) mod kinds_plane;
#[deny(unsafe_code)]
pub(crate) mod kinds_transport;
#[deny(unsafe_code)]
pub(crate) mod log_file;
#[deny(unsafe_code)]
pub(crate) mod plane_calls;
#[deny(unsafe_code)]
pub(crate) mod watchdog;
#[deny(unsafe_code)]
pub(crate) mod worker;
#[deny(unsafe_code)]
pub(crate) mod worker_unit_cancel;
