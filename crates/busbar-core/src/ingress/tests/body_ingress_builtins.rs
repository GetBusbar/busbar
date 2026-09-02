// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CORE'S OWN TEST-BINARY BODY-MODEL ARRIVAL LIST — `busbar_llm::BODY_INGRESS`, named HERE in a
//! `tests/` file the neutral-purity lint excludes so the neutral source (`ingress/mod.rs`) spells no
//! dialect crate. The body-axis twin of `tests/path_ingress_builtins.rs`: it reproduces, for the
//! pre-extraction fixture surface, the `(name, arrival)` pairs the composition root installs in
//! production, so a `/v1/messages` (named/adhoc) or body-model dispatch request in a core test
//! resolves its arrival through `busbar_substrate::ingress::arrival::body_ingress_for`.

use busbar_substrate::ingress::arrival::BodyIngress;

/// The shipped body-model arrivals for core's test binary — `busbar_llm::BODY_INGRESS` verbatim, so the
/// fixture registry matches a shipped LLM binary's.
pub(crate) fn test_body_ingress() -> &'static [(&'static str, BodyIngress)] {
    busbar_llm::BODY_INGRESS
}
