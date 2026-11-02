// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub trait PlaneDispatch: Send + Sync {
    fn execute<'a>(
        &'a self,
        op: busbar_contract::ids::OpClassId,
        drive: busbar_kernel::teller::RouteLeg<'a>,
    ) -> busbar_kernel::teller::RouteLeg<'a>;

    fn driven(&self) -> Option<u64> {
        None
    }
}

/// The seam's production half: the surface the plane already routes through, counted.
///
/// Deliberately the thinnest thing in the file. It awaits the leg it was handed and returns that
/// leg's own value — no decision is computed here, no byte is touched, and nothing is added to or
/// taken from the answer. **That is what makes byte identity a property of the construction rather
/// than of a measurement**: the future this returns awaits the future it was given.
///
/// The count is taken when the leg is FIRST POLLED and not when it is built, because those are two
/// different facts. A leg built and dropped — a unit whose client hung up between Admit and the
/// first poll — did not drive the engine, and a count taken at construction would say it did.
#[derive(Debug, Default)]
pub struct DrivenOnce {
    /// How many of this node's units have driven the seam, since the node was built.
    driven: std::sync::atomic::AtomicU64,
}

impl DrivenOnce {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn driven(&self) -> u64 {
        self.driven.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl PlaneDispatch for DrivenOnce {
    fn execute<'a>(
        &'a self,
        _op: busbar_contract::ids::OpClassId,
        drive: busbar_kernel::teller::RouteLeg<'a>,
    ) -> busbar_kernel::teller::RouteLeg<'a> {
        Box::pin(async move {
            self.driven
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            drive.await
        })
    }

    fn driven(&self) -> Option<u64> {
        Some(DrivenOnce::driven(self))
    }
}

#[cfg(test)]
#[path = "tests/transports.rs"]
mod tests;
