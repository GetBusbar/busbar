// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::{Digest32, Id, Identity};

/// Confirmation that the retained candidate's final checkpoint is durable and
/// the native session has authorized serving that same recovered backend.
/// There is deliberately no public constructor.
#[derive(Debug)]
pub struct CompletionReceipt {
    pub(crate) upgrade: Id,
    pub(crate) target: Identity,
    pub(crate) readiness: Digest32,
}

impl CompletionReceipt {
    pub fn upgrade_id(&self) -> Id {
        self.upgrade
    }
    pub fn target(&self) -> &Identity {
        &self.target
    }
    pub fn readiness_digest(&self) -> Digest32 {
        self.readiness
    }
}
