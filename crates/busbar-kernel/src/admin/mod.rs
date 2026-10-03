// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the kernel keeps of the operator surface: its own protocol-free verdicts and a little state.
//!
//! The operator surface — the route table, every handler, the frozen error taxonomy and its views,
//! the error envelope framing, the plane trust-verb backing and the mutation classifier — is the
//! admin cleanliness crate's (BUSBAR-1.6.0.md THE DESIGN §8; 1.6.0-TODO.md PATH TO
//! DEV-GREEN, D4). That crate depends on the kernel one way; the kernel reaches it only through the
//! fn-pointer seam in [`seam`], registered once by the composition root.
//!
//! What stays here:
//!
//! * [`refusal`] — the answers the kernel's gate gives before any admin handler runs (a code, a
//!   status number, a message, the envelope bytes) and the operation→scope matrix it judges with.
//! * [`seam`] — the mount and the mutation classifier the admin crate installs.
//! * [`versions`] — the [`versions::VersionLog`] config-version store, a field of `state::App`.

pub mod refusal;
pub mod seam;
pub mod versions;

pub use refusal::{envelope, required_scope, Refusal};
