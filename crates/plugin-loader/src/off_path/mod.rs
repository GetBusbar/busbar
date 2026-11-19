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

// Kept at its path (the unsafe register, unsafe.yaml, pins its count per file).
#[path = "../durable_documents.rs"]
pub(crate) mod durable_documents;
