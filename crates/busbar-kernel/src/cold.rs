// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COLD MODULE (LINT-RULES LR-167): the cold code the kernel's request-path modules need,
//! called out of line: refusal text, spelled only when a request, a unit or a definition is
//! refused, and the first-sight paths that key a name once and then share it. Every fn is
//! `#[cold]` or `#[inline(never)]`; none holds a loop or sweeps request data (BP17). Each section
//! is named for the request-path module it serves.

// Sections as submodules (cold/<section>.rs), so the slices that fill them do not collide.
pub(crate) mod auth;
pub(crate) mod governance;
pub(crate) mod host;
