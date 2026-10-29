// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The protections over core's own production source that a customer depends on: money is
//! integers and a view, secret material is typed and never logged or served, and a 1.5.x config
//! still reads. Each rule names the file and line it refuses.

mod config;
mod credential_typecheck;
mod secrets;
mod walk;
mod workflows;
