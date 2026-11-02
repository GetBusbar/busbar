// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod the_runtime_half;

mod what_the_record_reads;

mod the_posting_arithmetic;

mod what_the_usage_report_says;

mod bounded_limits;

mod destination_kinds;

#[cfg(not(target_env = "msvc"))]
mod capability_binding_zero_cost;
