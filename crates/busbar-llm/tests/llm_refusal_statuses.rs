// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LLM PLANE'S REFUSAL STATUSES, AS THE PLANE DRIVER CHOOSES THEM, AGAINST 1.5.5.
//!
//! It sits in the llm engine crate, the one crate that already names both the kernel's driver and
//! the plane, until the engine's deletion moves it beside the oracle's cells of the flip.
//!
//! The kernel's plane driver chooses a refusal's status from the plane's stated rows, else its own
//! default. For every refusal the previous release recorded (the shadow oracle's golden cells,
//! read here and never written), the status the driver chooses for the plane's dialect and the
//! refusal's reason equals the recorded status. A row missing from the plane's statement, or one
//! that says something the recording does not, is RED here.

use std::path::{Path, PathBuf};

use busbar_contract::caps::ReasonCode;
use busbar_kernel::plane_driver::{refusal_status, BufferCaps, DriverConfig};
use busbar_plane_llm::dialect::DIALECTS;
use busbar_plane_llm::refusal::REFUSAL_STATUSES;

fn golden() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/shadow-oracle/golden/1.5.5/cells")
}

/// The status a recorded cell answered.
fn recorded(cell: &str) -> u32 {
    let path = golden().join(format!("{cell}.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("the recording {} is readable: {e}", path.display()));
    let json: serde_json::Value = serde_json::from_str(&text).expect("a recording is JSON");
    json["status"]
        .as_u64()
        .unwrap_or_else(|| panic!("{cell} records a status")) as u32
}

fn config() -> DriverConfig {
    DriverConfig {
        caps: BufferCaps::default(),
        op_classes: Vec::new(),
        status_of: refusal_status,
        refusal_statuses: REFUSAL_STATUSES.to_vec(),
        caller_refs: None,
    }
}

fn dialect(name: &str) -> u32 {
    DIALECTS
        .iter()
        .position(|d| d.name == name)
        .unwrap_or_else(|| panic!("the plane states {name}")) as u32
}

const SIX: [&str; 6] = [
    "anthropic",
    "openai",
    "gemini",
    "bedrock",
    "responses",
    "cohere",
];

/// Every recorded refusal of one condition, per dialect, with the reason the kernel refuses it for.
fn every_dialect(condition: &str, reason: ReasonCode) -> Vec<(String, &'static str, ReasonCode)> {
    SIX.iter()
        .map(|d| (format!("llm__{d}__{d}__request__{condition}"), *d, reason))
        .collect()
}

#[test]
fn every_recorded_llm_refusal_wears_the_status_the_driver_chooses() {
    let config = config();
    let mut cells = Vec::new();
    // No credential resolved to a principal: 401, but 403 on bedrock and 400 on gemini.
    cells.extend(every_dialect(
        "unauthenticated",
        ReasonCode::Unauthenticated,
    ));
    // A spend cap: 429, but 400 on bedrock.
    cells.extend(every_dialect("over_budget_total", ReasonCode::OverBudget));
    // A count cap (requests per day): 429 everywhere.
    cells.extend(every_dialect("over_budget", ReasonCode::RateLimited));
    // A body the plane cannot read: 400 everywhere.
    cells.extend(every_dialect("malformed", ReasonCode::DecodeFailed));
    // Every member down, every ingress dialect against every far-end dialect: 503.
    for ingress in SIX {
        for far in SIX {
            cells.push((
                format!("llm__{ingress}__{far}__request__upstream_down"),
                ingress,
                ReasonCode::DestinationUnreachable,
            ));
        }
    }
    cells.push((
        "route.failover__fo__all-down".into(),
        "openai",
        ReasonCode::DestinationUnreachable,
    ));
    // An oversized body: 413.
    for (cell, d) in [
        ("http.crosscut__413__anthropic", "anthropic"),
        ("http.crosscut__413__openai", "openai"),
        ("http.crosscut__413__gemini-path", "gemini"),
    ] {
        cells.push((cell.into(), d, ReasonCode::BodyTooLarge));
    }
    // A model no rate prices, under a configured rate card: 400.
    cells.push((
        "http.crosscut__unknown-path__openai-suffix".into(),
        "openai",
        ReasonCode::NoRate,
    ));
    let mut wrong = Vec::new();
    for (cell, d, reason) in &cells {
        let chosen = config.status(dialect(d), *reason);
        let want = recorded(cell);
        if chosen != want {
            wrong.push(format!(
                "{cell}: {d} {reason:?} chose {chosen}, 1.5.5 answered {want}"
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {}:\n{}",
        wrong.len(),
        cells.len(),
        wrong.join("\n")
    );
}

/// Each stated row is needed: the kernel's default alone answers something 1.5.5 did not.
#[test]
fn every_stated_row_differs_from_the_kernel_default() {
    for row in REFUSAL_STATUSES {
        let reason = busbar_contract::abi::plane::reason_of(row.reason).expect("a known reason");
        assert_ne!(
            refusal_status(reason),
            row.status,
            "{reason:?} in dialect {} restates the default",
            row.dialect
        );
    }
}

/// The plane's rows pass the load-time validator against the dialects it states.
#[test]
fn the_rows_pass_the_validator() {
    assert_eq!(
        busbar_contract::abi::plane::check::check_refusal_statuses(
            &REFUSAL_STATUSES,
            DIALECTS.len() as u64
        ),
        Ok(())
    );
}
