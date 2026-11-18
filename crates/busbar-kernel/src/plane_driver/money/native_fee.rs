// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Read-only completion of the original fee account, independent of live participation.

use std::sync::Arc;

use super::FeeParticipation;
use crate::governance::unit_checkpoint::partitions::{
    CapturedFee, FeeBasis, SelectedFeeCompletion,
};

impl FeeParticipation {
    /// Capture before transferring terminal custody, then consume the actual participation at
    /// its normal terminal point. Retaining this observer cannot prevent final fee completion.
    pub(super) fn selected_fee(&self) -> (CapturedFee, Option<Arc<SelectedFeeCompletion>>) {
        let charge = &self.account.money.charge;
        let basis = FeeBasis {
            lane: charge.fee_lane().map(str::to_owned),
            era: charge.raw_era(),
        };
        if !self.owner {
            return (CapturedFee::NotOwner { basis }, None);
        }
        let completion = Arc::clone(&self.account.completion);
        match completion.observe() {
            Some(result) => (CapturedFee::ResolvedOwner { basis, result }, None),
            None => (CapturedFee::PendingOwner { basis }, Some(completion)),
        }
    }
}
