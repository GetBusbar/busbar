// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// Cold code for the request-path `auth` tree: refusal and diagnostic text and rare off-path work.
// One submodule per slice of `auth`, so the slices that feed it do not collide.

pub(crate) mod chain;
pub(crate) mod keys;
pub(crate) mod login;
pub(crate) mod sight;
