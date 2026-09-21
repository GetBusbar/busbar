// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CORE'S OWN TEST-BINARY PATH-MODEL ARRIVAL LIST — `busbar_llm::PATH_INGRESS`, named HERE in a
//! `tests/` file the neutral-purity lint excludes so the neutral source (`ingress/path_ingress.rs`)
//! spells no dialect crate. The exact analogue of `proto/tests/registry_builtins.rs` for the arrival
//! side-table: it reproduces, for the pre-extraction fixture surface, the `(name, arrival)` pairs the
//! composition root installs in production, so a gemini/bedrock URL-model request in a core test
//! resolves its arrival through `busbar_substrate::ingress::arrival::path_ingress_for`.

use busbar_substrate::ingress::arrival::PathIngress;

/// The shipped URL-model arrivals for core's test binary: gemini's and bedrock's, keyed by name —
/// `busbar_llm::PATH_INGRESS` verbatim, so the fixture registry matches a shipped LLM binary's.
pub(crate) fn test_path_ingress() -> &'static [(&'static str, PathIngress)] {
    busbar_llm::PATH_INGRESS
}
