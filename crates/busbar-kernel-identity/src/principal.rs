// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one caller who is nobody.

/// The literal an unauthenticated caller renders as, on every surface that names an actor: the
/// audit row, the chain hash and the idempotency namespace all spell it this way, so nothing that
/// reads an actor id has to know whether a principal was resolved.
///
/// The internal attribution bucket for anonymous traffic is a different string entirely and never
/// reaches a surface; the anonymous principal itself carries no bucket at all.
pub const ANONYMOUS: &str = "anonymous";
