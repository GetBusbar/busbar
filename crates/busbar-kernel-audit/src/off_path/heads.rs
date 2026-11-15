// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The head history's whole-series copy: what a restore check or an inspection reads, never a
//! request.

use crate::heads::{HeadHistory, SignedHead};

impl HeadHistory {
    /// Every anchor this node can offer, in position order: the series, then the tip if the tip is
    /// not already its last sample.
    #[must_use]
    pub fn anchors(&self) -> Vec<SignedHead> {
        let mut out = self.series().to_vec();
        if let Some(tip) = self.tip() {
            if out.last().map(|h| h.seq) != Some(tip.seq) {
                out.push(tip.clone());
            }
        }
        out
    }
}
