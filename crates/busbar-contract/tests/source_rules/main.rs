// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The protections over core's own production source that a customer depends on: money is

mod boot_advice;
mod buffered_numbers;
mod candidate_once;
mod config;
mod count_gate;
mod credential_typecheck;
mod derive_once;
mod escape_scope;
mod escapes;
mod lane_qualifier;
mod refusal_reason;
mod rt_builders;
mod secrets;
mod uncounted_cap;
mod walk;
mod workflows;
