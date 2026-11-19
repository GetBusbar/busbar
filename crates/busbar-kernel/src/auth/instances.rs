// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH PROVIDERS OF ONE CONFIG BUILD, keyed by provider name (the `identity-providers` key).
//!
//! Every item here runs at a config build, a reload or an admin flush, never per request, so the
//! code lives off the request path in `crate::off_path::auth::keys::instances`; these are its
//! names on the auth surface.

pub use crate::off_path::auth::keys::instances::flush_distinct;
pub(crate) use crate::off_path::auth::keys::instances::provider_settings;
