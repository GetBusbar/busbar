// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LLM PLANE DOOR'S ROOT CELLS, as the composition root's door-cells row reads them: this file
//! is the one this crate states under its `links` name (`build.rs`, `cargo::metadata=cells=`),
//! compiled as a child of the composition root's serve module in its test builds (`super::` is
//! `root::serve`). The kernel and the loader are the root's to link, never a plane's, so this
//! directory has no `main.rs`, and `cargo test -p busbar-plane-llm` does not build it.
//!
//! What it states is the plane's answer to the capability-equality ledger: its column, and the
//! root-leg cells the ledger marks not applicable on it, reason for reason, which the composition
//! root holds equal to the ledger's (`root/tests/door_cells.rs`). The leg's proven cells are where
//! the ledger's `root_legs` row `root-llm` names them
//! (`crates/busbar/src/root/tests/plane_node.rs`); the door's secret-source driver is the
//! composition root's own (`root/tests/secret_source.rs`, the pools door of its driver proofs).

/// THIS PLANE'S CAPABILITY-EQUALITY COLUMNS (`qa/capability-equality.json`): the cells its root leg
/// answers for.
pub(crate) const COLUMNS: &[&str] = &["llm"];

/// `(capability, column, reason)`: the root-leg cells this plane is NOT owed, each the ledger's own
/// not-applicable cell with its reason, word for word. The composition root holds the two equal: a
/// plane opts out of nothing the ledger says it has, and the ledger excuses nothing the plane does
/// not state.
pub(crate) const NOT_APPLICABLE: &[(&str, &str, &str)] = &[
    (
        "trust-pinning",
        "llm",
        "LLM providers are operator-declared config endpoints, not peer-published artifacts; there is no upstream-authored schema or card to pin. The trust lifecycle governs artifacts a peer authors.",
    ),
    (
        "net-guard",
        "llm",
        "LLM egress targets are operator-configured provider endpoints; no request-authored URL reaches the LLM egress path, so there is no SSRF surface -- which is why grep finds no net_guard consumer under proxy/.",
    ),
];

/// THE SECRET-SOURCE SCAN'S DRIVEN DOOR (the composition root's `secret_source.rs`, which holds
/// every linked door plane to a driver): the Statement names the cells in this file drive. None:
/// this door's driver is the composition root's own (see the module docs), so this file adds no
/// name to the scan.
pub(crate) fn secret_source_driven() -> Vec<String> {
    Vec::new()
}
