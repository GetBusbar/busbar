// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RFC 9449 DPoP AT THE RESOURCE: sender-constrained tokens on busbar's own data plane.

/// Whether `token` is bound to a DPoP key (RFC 9449 s6: `cnf.jkt`).
pub fn is_dpop_bound(_token: &str) -> bool {
    unimplemented!("red: RFC 9449 s7.1")
}

#[cfg(test)]
#[path = "tests/dpop_tests.rs"]
mod dpop_tests;
