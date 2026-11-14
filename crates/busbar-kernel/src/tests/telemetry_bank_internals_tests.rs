// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub use super::HIST_DRAIN_THRESHOLD;

pub fn hist_chunk_materialized(slot: super::HistogramSlot) -> bool {
    let idx = slot.0 as usize;
    super::BANK.with(|bank| bank.hists[idx / super::HIST_CHUNK].get().is_some())
}
