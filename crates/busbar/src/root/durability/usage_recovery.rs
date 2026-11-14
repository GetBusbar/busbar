// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Root capability wiring for the core-owned native recovery journal.

use std::sync::Arc;

use busbar_kernel::governance::persistence::recovery::StoreRecovery;
use busbar_kernel::governance::recovery::{RecoveryError, RecoverySink};
use busbar_kernel::persistence::journal::runtime::RuntimeJournal;

pub(crate) fn usage_recovery_sink(
    journal: Arc<RuntimeJournal>,
) -> Result<Arc<dyn RecoverySink>, RecoveryError> {
    Ok(Arc::new(StoreRecovery::new(
        journal,
        busbar_kernel::teller::Kernel::new().durability_token(),
    )?))
}
