// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ADMIN SURFACE'S PATH VOCABULARY, as the config grammar and the admin middleware both read
//! it. It is here, with the value grammar, because the config validator RESERVES the first path
//! segment from it — a pool, provider or model named `api` must not be able to shadow the admin
//! surface — and a reserved name that is not derived from the thing it reserves against is a
//! reserved name that drifts. It did: the reserved word still guarded `admin` long after the admin
//! surface moved to `/api`, so a deployment could configure a lane called `api` that validated
//! cleanly and was then routed to the admin plane. `busbar-substrate` re-exports both constants at
//! `busbar_substrate::config::admin::`, and its `admin_verbs` module re-exports them at the
//! spelling the middleware has always used.

/// THE NATIVE-API ROOT — the exact `/api` path every busbar-own surface mounts under, and the ONE
/// constant the admin auth middleware classifies a request as admin with.
///
/// It lives on the neutral admin seam rather than inside the middleware because a SECOND reader
/// needs it and must never carry a copy: the config validator reserves the first path segment
/// (`api`) so a pool, provider or model named `api` cannot shadow the admin surface. Those two
/// used to hold separate literals, and they DRIFTED — the reserved name still guarded `admin` long
/// after the admin surface moved here, so a deployment could configure a lane called `api` that
/// validated cleanly and was then routed to the admin plane.
pub const ADMIN_PATH: &str = "/api";

/// The `/api/` prefix that all native-API sub-routes share. A path must match [`ADMIN_PATH`]
/// exactly OR start with this to be treated as an admin-plane request — preventing sibling paths
/// like `/apix/…` from being mis-classified. The WHOLE `/api/` root is admin-classified
/// (fail-closed): a future area (`events`, `metrics`) mounted under `/api/` is admin-guarded by
/// default and must explicitly carve out a weaker class if it ever wants one.
pub const ADMIN_PATH_PREFIX: &str = "/api/";
