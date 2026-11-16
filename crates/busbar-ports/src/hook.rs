// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hook port (IF §11.3). W0-ABI stub: frozen signatures, `todo!()` bodies; L6 fills it.

use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::kinds::hook::hook::CandidateRec;

use crate::{CallCx, FactRef, PortError};

/// What core puts in a hook view (encoded once per decision point by `hook::encode_view`, §8.8).
/// Round 17: K8 puts S_STAGE (FACT, `abi::hook::STAGE_*`) in `signals` for every stage tap (from today's
/// `HookStage::{Candidate, Routing, Response}`, kernel config/hooks.rs:190-195) and S_STAGE_MODEL (FACT_TEXT) when
/// the attempt has a model; neither on a request-stage call. No field is added: both ride `signals`.
pub struct HookView<'a> {
    pub signals: &'a [(u32, FactRef<'a>)],
    pub candidates: &'a [CandidateIn<'a>],
    /// Round 6: the budget buckets that apply to this request (BUDGET*).
    pub budgets: &'a [BudgetIn<'a>],
    pub conversation: Option<&'a [u8]>,
    pub body: Option<&'a [u8]>,
    pub identity: Option<&'a [u8]>,
}

/// `rec.flags` carries the C_HAS_* bits; K8 sets a bit exactly when today's projection would include the field.
pub struct CandidateIn<'a> {
    pub rec: CandidateRec,
    pub model: &'a str,
    pub provider: &'a str,
    pub tier: Option<&'a str>,
    pub tags: &'a [&'a str],
    pub cost_terms: &'a [CostTermIn<'a>],
}

pub struct BudgetIn<'a> {
    pub id: &'a str,
    pub period: &'a str,
    pub group: Option<&'a str>,
    pub pool: Option<&'a str>,
    pub remaining_micros: i64,
    pub spend_micros_at_current_rate: Option<i64>,
    pub window_start_s: u64,
}

/// Built by K8 per candidate from the member's rate card and the request's expected units (EXPECT, else the
/// D_USAGE_CLASS default); price None = unpriced (COST_UNPRICED).
pub struct CostTermIn<'a> {
    pub class: &'a str,
    pub price_per_unit: Option<f64>,
    pub expected_units: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct HookAnswer {
    pub verb: u32,
    pub reject_status: Option<u16>,
    pub order: Vec<u32>,
    pub restrict: Vec<Box<str>>,
    pub message: Option<Box<str>>,
    pub rewrite: Option<Vec<u8>>,
}

pub enum HookCall<'a> {
    Done(Result<HookAnswer, PortError>),
    Io(BoxFut<'a, Result<HookAnswer, PortError>>),
}

pub trait HookPort: Send + Sync + 'static {
    fn points(&self) -> u32;
    fn facts(&self) -> u64;
    fn on<'a>(&'a self, cx: CallCx, point: u32, view: &'a HookView<'a>) -> HookCall<'a>;
}
