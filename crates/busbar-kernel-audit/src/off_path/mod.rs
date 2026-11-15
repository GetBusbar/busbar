// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUDIT REQUEST-PATH MODULES' OFF-PATH CODE: what they need once per restore, per
//! configuration or per process lifecycle (a journal read back from durable storage, a signing key
//! loaded, a held run copied out for a restore), never per request. It sits outside the
//! request-path marker because it does not run per request; the request path only reads what it
//! built. Each submodule is named for the request-path module it builds for.

pub(crate) mod amend;
pub(crate) mod heads;
pub(crate) mod journal;
pub(crate) mod sign;
