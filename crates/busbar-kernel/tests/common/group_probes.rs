// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use super::units::TestUnits;

pub struct CappedGroup {
    live: Arc<AtomicUsize>,
    cap: usize,
}

impl CappedGroup {
    pub fn at(cap: usize) -> Arc<Self> {
        Arc::new(CappedGroup {
            live: Arc::new(AtomicUsize::new(0)),
            cap,
        })
    }

    pub fn live(&self) -> usize {
        self.live.load(Ordering::Acquire)
    }

    // `fetch_update` is deprecated in favour of `try_update` (Rust 1.95+); this crate's
    // MSRV floor is below 1.95, so keep the older name.
    #[allow(deprecated)]
    fn count_one(&self) -> Option<GroupCount> {
        self.live
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.cap).then_some(n + 1)
            })
            .ok()
            .map(|_| GroupCount(Arc::clone(&self.live)))
    }
}

struct GroupCount(Arc<AtomicUsize>);

impl Drop for GroupCount {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl TestUnits {
    pub fn in_groups(groups: &[&'static str]) -> Self {
        TestUnits {
            groups: groups.to_vec(),
            ..TestUnits::default()
        }
    }

    pub(crate) fn behind(group: &Arc<CappedGroup>) -> Self {
        let group = Arc::clone(group);
        TestUnits {
            capped: Some(Arc::new(
                move |leases: &busbar_kernel::slice::GroupLeaseSlip| {
                    let Some(counted) = group.count_one() else {
                        return false;
                    };
                    leases.holding(busbar_kernel::slice::DoorGrant::new(counted));
                    true
                },
            )),
            ..TestUnits::default()
        }
    }

    pub fn doors(&self) -> (bool, bool) {
        (
            self.refused_door.load(Ordering::Acquire),
            self.admitted_door.load(Ordering::Acquire),
        )
    }
}
