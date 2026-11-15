// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// The crate's one sanctioned cold module (busbar-bad-patterns BP17): cold code the request-path
// modules need (refusal and diagnostic text, rare off-path work) lives here, outside the
// request-path marker, and the marked modules call into it. Every fn here is #[cold] or
// #[inline(never)], holds no while/loop, and never sweeps request data. One submodule per owning
// area, so the slices that feed it do not collide.

pub(crate) mod auth;
pub(crate) mod host;
