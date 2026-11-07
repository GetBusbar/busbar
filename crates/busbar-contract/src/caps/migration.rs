// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The migration library's sealed access to protected host recovery material.

/// Root token delivered only to the migration library's private holder.
#[derive(Debug)]
pub struct MigrationSeal(());

/// Read access minted by the migration library; it cannot mint kernel work,
/// accounting or administrative tokens.
#[derive(Debug)]
pub struct MigrationGrant(());

impl MigrationSeal {
    /// Deliver a fresh root token to the one migration root symbol. Its private
    /// holder cannot be downcast or opened by another crate.
    #[doc(hidden)]
    #[inline]
    pub fn deliver() -> Box<dyn std::any::Any + Send + Sync> {
        crate::abi::migration_root(Self(()))
    }
    /// Lend protected recovery access without lending the root token itself.
    pub fn grant(&self) -> MigrationGrant {
        MigrationGrant(())
    }

    /// Test-only root token; absent from production artifacts.
    #[cfg(feature = "test-seal")]
    pub fn acquire_for_migrations() -> Self {
        Self(())
    }
}
impl crate::plugin::sealed::KernelSealed for MigrationGrant {}
impl crate::plugin::KernelSeal for MigrationGrant {
    fn seal_origin(&self) -> &'static str {
        "busbar-migrations"
    }
}
