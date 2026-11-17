// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Read-only completion of the original fee account, independent of live participation.

use std::sync::Arc;

use super::{locked, FeeAccount, FeeParticipation};
use crate::governance::unit_checkpoint::partitions::{
    CapturedFee, FeeBasis, FeeResult, SelectedFeeCompletion,
};

struct FeeCompletion(Arc<FeeAccount>);

impl SelectedFeeCompletion for FeeCompletion {
    fn observe(&self) -> Option<FeeResult> {
        locked(&self.0.state).completed
    }
}

impl FeeParticipation {
    /// Capture before transferring terminal custody, then consume the actual participation at
    /// its normal terminal point. Retaining this observer cannot prevent final fee completion.
    pub(super) fn selected_fee(&self) -> (CapturedFee, Option<Arc<dyn SelectedFeeCompletion>>) {
        let charge = &self.account.money.charge;
        let basis = FeeBasis {
            lane: charge.fee_lane().map(str::to_owned),
            era: charge.raw_era(),
        };
        if !self.owner {
            return (CapturedFee::NotOwner { basis }, None);
        }
        let completion = Arc::new(FeeCompletion(self.account.clone()));
        match completion.observe() {
            Some(result) => (CapturedFee::ResolvedOwner { basis, result }, None),
            None => (CapturedFee::PendingOwner { basis }, Some(completion)),
        }
    }
}
