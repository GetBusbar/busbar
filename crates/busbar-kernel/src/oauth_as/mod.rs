// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BUSBAR AS AN OAUTH 2.1 AUTHORIZATION SERVER (`oauth_as:`), off unless configured: the kernel's
//! side of it is only the [`seam`].
//!
//! The authorization server's runtime (its routes, consent screen, client registration, client
//! metadata fetch and signer) and its `oauth_as:` config types live in the sibling
//! `busbar-core-oauth2` crate, which depends on `busbar-kernel` one-way. The kernel carries the
//! block as an OPAQUE value and reaches the server only through the fn-pointer set in
//! [`seam::AsPlaneSeam`], registered once by the composition root: [`seam::AsPlaneSeam::check`]
//! validates the block and lists its secret references, [`seam::AsPlaneSeam::build`] builds the
//! type-erased runtime object for one config generation, [`seam::AsPlaneSeam::mount`] mounts its
//! routes, and [`seam::AsPlaneSeam::verify_dpop`] verifies a DPoP presentation at a protected
//! resource. The kernel never names those types.
//!
//! OFF COSTS NOTHING: with no `oauth_as:` block no runtime object is built, so `mount` is handed
//! `None` and mounts no route, and nothing is stored, signed or swept.

pub mod seam;

// THE CONFIG (`OauthAsCfg`/`AsIdentity`) and its tests live in `busbar-core-oauth2` with the plane that
// reads them: the kernel carries the `oauth_as:` block as an opaque value and asks its owner, through
// [`seam::AsPlaneSeam::check`], to validate it.
