// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LLM PLANE'S REFUSAL STATUSES, AS THE PLANE DRIVER CHOOSES THEM, AGAINST 1.5.5 (coverage map
//! v2 rows 743, 744 and 746, the legacy crate's `tests/llm_refusal_statuses.rs`).
//!
//! These cases need the kernel's plane driver and this plane's stated rows together, which only the
//! composition root links. Their map home was the root's own test crate, and they are compiled into
//! the root's test binary from here (the driver-proofs row): the root's sources name no plane and
//! no dialect, and these cases are written in this plane's words.
//!
//! The kernel's plane driver chooses a refusal's status from the plane's stated rows, else its own
//! default. For every refusal the previous release recorded (the shadow oracle's golden cells, read
//! here and never written), the status the driver chooses for the plane's dialect and the refusal's
//! reason equals the recorded status.

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
    u32::try_from(
        json["status"]
            .as_u64()
            .unwrap_or_else(|| panic!("{cell} records a status")),
    )
    .expect("a status")
}

/// Recorded refusals whose 1.6.0 status is an owner-accepted difference from 1.5.5: the cell, the
/// status 1.6.0 answers, and the `id` of its entry in `testing/shadow-oracle/accepted-differences.json`
/// (asserted present and naming the cell, so this list can never forgive more than the register does).
/// PR #958: a Bedrock caller whose budget is spent is refused 429 `ThrottlingException`.
const ACCEPTED: &[(&str, u32, &str)] = &[(
    "llm__bedrock__bedrock__request__over_budget_total",
    429,
    "C-22 bedrock budget refusal is a declared Converse error",
)];

/// The status 1.6.0 owes for `cell`: the accepted difference's, else the recording's.
fn owed(cell: &str) -> u32 {
    let Some((_, status, id)) = ACCEPTED.iter().find(|(c, _, _)| *c == cell) else {
        return recorded(cell);
    };
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testing/shadow-oracle/accepted-differences.json");
    let text = std::fs::read_to_string(&path).expect("the register is readable");
    let register: serde_json::Value = serde_json::from_str(&text).expect("the register is JSON");
    let entry = register["accepted"]
        .as_array()
        .expect("the register holds `accepted`")
        .iter()
        .find(|e| e["id"].as_str() == Some(*id))
        .unwrap_or_else(|| panic!("accepted difference {id:?} is in the register"));
    let id_form = cell.replace("__", "\\|");
    assert!(
        entry["cells"]
            .as_str()
            .is_some_and(|c| c.contains(&id_form)),
        "accepted difference {id:?} names {cell}"
    );
    assert!(
        entry["classes"]
            .as_array()
            .is_some_and(|c| c.iter().any(|v| v == "status")),
        "accepted difference {id:?} accepts the status class"
    );
    *status
}

/// The driver's configuration over this plane's stated rows, as the root composes it.
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
    u32::try_from(
        DIALECTS
            .iter()
            .position(|d| d.name == name)
            .unwrap_or_else(|| panic!("the plane states {name}")),
    )
    .expect("a dialect index")
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

/// LEGACY `crates/busbar-llm/tests/llm_refusal_statuses.rs::every_recorded_llm_refusal_wears_the_status_the_driver_chooses`
/// (coverage map v2 row 743). 1.5.5: every recorded llm refusal wears the status the driver now
/// chooses: unauthenticated 401 (403 on bedrock, 400 on gemini), a spend cap 429 (1.5.5 answered
/// 400 on bedrock; 1.6.0 answers 429 there too, PR #958, see `ACCEPTED`), a count cap 429, an unreadable body 400, every member down 503 for every ingress and far
/// dialect, an oversized body 413, and a model no rate prices 400.
///
/// RED: a stated row goes missing, or a row says something the recording does not.
#[test]
fn every_recorded_llm_refusal_wears_the_status_the_driver_chooses() {
    let config = config();
    let mut cells = Vec::new();
    cells.extend(every_dialect(
        "unauthenticated",
        ReasonCode::Unauthenticated,
    ));
    cells.extend(every_dialect("over_budget_total", ReasonCode::OverBudget));
    cells.extend(every_dialect("over_budget", ReasonCode::RateLimited));
    cells.extend(every_dialect("malformed", ReasonCode::DecodeFailed));
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
    for (cell, d) in [
        ("http.crosscut__413__anthropic", "anthropic"),
        ("http.crosscut__413__openai", "openai"),
        ("http.crosscut__413__gemini-path", "gemini"),
    ] {
        cells.push((cell.into(), d, ReasonCode::BodyTooLarge));
    }
    cells.push((
        "http.crosscut__unknown-path__openai-suffix".into(),
        "openai",
        ReasonCode::NoRate,
    ));
    let mut wrong = Vec::new();
    for (cell, d, reason) in &cells {
        let chosen = config.status(dialect(d), *reason);
        let want = owed(cell);
        if chosen != want {
            wrong.push(format!(
                "{cell}: {d} {reason:?} chose {chosen}, 1.6.0 owes {want}"
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

/// LEGACY `crates/busbar-llm/tests/llm_refusal_statuses.rs::every_stated_row_differs_from_the_kernel_default`
/// (coverage map v2 row 744). 1.5.5's statuses are kept with no dead row: every row the plane
/// states differs from the kernel's default for its reason, so each one is needed.
///
/// RED: a row restates the kernel default (dead weight that hides a later default change).
#[test]
fn every_stated_row_differs_from_the_kernel_default() {
    assert!(!REFUSAL_STATUSES.is_empty(), "the plane states its rows");
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

/// LEGACY `crates/busbar-llm/tests/llm_refusal_statuses.rs::p_item_refusal_reason_collapse_no_llm_refusal_reads_as_an_internal_error`
/// (coverage map v2 row 746). 1.5.5 answered every limit reason with its own status and kind and
/// none of them as an internal error: for every dialect and every reason the driver can refuse
/// for, the status it chooses is never a bare 500, and the kind the plane renders is the generic
/// `api_error` only for the node's own faults and for a timeout (whose 504 is its own status).
///
/// RED: a reason collapses into a bare 500, or a limit reason reads as the generic internal kind.
#[test]
fn p_item_refusal_reason_collapse_no_llm_refusal_reads_as_an_internal_error() {
    use busbar_contract::abi::plane::{class_of, RefusalClass};
    use busbar_plane_llm::exchange::refuse::kind_of;
    let config = config();
    let mut wrong = Vec::new();
    for d in SIX {
        for reason in ReasonCode::ALL {
            let class = class_of(*reason);
            let status = config.status(dialect(d), *reason);
            let kind = kind_of(reason.as_str(), u16::try_from(status).expect("a status"));
            if status == 500 {
                wrong.push(format!("{d} {reason:?} answers a bare 500"));
            }
            let generic = kind == busbar_contract::protocol::KIND_API_ERROR;
            if generic != (class.is_node_fault() || class == RefusalClass::Timeout) {
                wrong.push(format!(
                    "{d} {reason:?} ({class:?}) reads as {kind} at {status}"
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
