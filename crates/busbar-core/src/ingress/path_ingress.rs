// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PATH-MODEL ARRIVAL SIDE-REGISTRATION — the CORE-TEST seeding veneer over the neutral
//! [`busbar_substrate::ingress::arrival`] table.
//!
//! The mechanism (the `PathIngress` fn-pointer type, the installed side-table, `install_path_ingress`,
//! `path_ingress_for`) lives in `busbar-substrate` so the extracted dialect crate (`busbar-llm`) names
//! the registration-pair type and its arrivals live there, calling core back through the neutral
//! `ArrivalHost` seam rather than core holding them. The composition root names no `PathIngress`
//! spelling at all (the `busbar_core::ingress::PathIngress` re-export is deleted); the one remaining
//! reader of the re-export below is `proto::registry`, which re-points when that file's owner lands.
//! What this module keeps is the seeding around `path_ingress_for`.

pub use busbar_substrate::ingress::arrival::{install_path_ingress, PathIngress};

// PRODUCTION / `test-support`: the catch-all resolves an arrival straight off the installed table (the
// composition root wrote it; a `test-support` consumer seeds the hook via `busbar_llm::testkit`).
#[cfg(not(test))]
pub(crate) use busbar_substrate::ingress::arrival::path_ingress_for;

/// CORE'S OWN `#[cfg(test)]` BINARY has no composition root, so — exactly as `proto::registry`'s test
/// accessor seeds `set_test_builtins` — this seeds the neutral arrival hook with the extracted
/// dialects' `PATH_INGRESS` slice (named in a `tests/` file the neutral-purity lint excludes) before
/// every resolve, so a gemini/bedrock URL-model request in a core test resolves its arrival.
#[cfg(test)]
pub(crate) fn path_ingress_for(
    name: &str,
) -> Option<busbar_substrate::ingress::arrival::PathIngress> {
    busbar_substrate::ingress::arrival::set_test_path_ingress(test_path_ingress::test_path_ingress);
    busbar_substrate::ingress::arrival::path_ingress_for(name)
}

/// The extracted-dialect arrival list for core's OWN test binary — `busbar_llm::PATH_INGRESS`, named
/// in a `tests/` file the neutral-purity lint excludes so the neutral source spells no dialect crate.
#[cfg(test)]
#[path = "tests/path_ingress_builtins.rs"]
mod test_path_ingress;
