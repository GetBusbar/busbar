// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Public typed store test facade. Requires the existing dev-only `test-seal` feature.
//! The store adapter's test authority is installed internally and is never returned to callers.

use crate::fake_needs::FakeNeeds;
use crate::suites::harness::Harness;
use busbar_contract::plugin::TestKernelSeal;
use busbar_plugin_abi::plugin::__rt::LinkedPlugin;
use busbar_plugin_abi::plugin::Plugin;
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_loader::admit::Admitted;
use std::future::Future;

pub use busbar_contract::abi::sdk::store::v4::conformance;
pub use busbar_contract::persistence::{
    control, Address, AttemptId, BackendInfo, Call, Candidate, ClockObservation, CommitKey,
    DatasetId, Decision, Durability, ExpectedValue, Failure, InvalidCandidate, Mutation,
    NamespaceId, Page, PersistenceBackend, Predicate, PreparedCandidate, Read, ReadResult, Scan,
    SelfFenced, TimeGuard, CANDIDATE_VERSION, MAX_SLOTS,
};
pub use busbar_contract::Secret;
pub use busbar_plugin_abi::host_side::caller::{Accept, InstanceLimits};
pub use busbar_plugin_loader::instance::OpenError;
pub use busbar_plugin_loader::refusal::{Refusal, RefusalCode};
pub use busbar_ports::store::StoreHandle;

/// One suite case's configured instance and fresh dataset. Names/config are supplied by the plugin,
/// so database schema/table restrictions are not guessed by the SDK.
pub struct StoreCase {
    pub name: String,
    pub config: Vec<u8>,
    pub limits: InstanceLimits,
}
impl StoreCase {
    pub fn new(name: impl Into<String>, config: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            config,
            limits: InstanceLimits::default(),
        }
    }
}

/// A normal MIN-3 harness with its store-only test capability installed internally.
pub struct StoreHarness {
    inner: Harness,
}
impl StoreHarness {
    pub fn admit(plugin: &'static Plugin, needs: FakeNeeds) -> Result<Self, Refusal> {
        Self::from_harness(Harness::admit(plugin, needs)?)
    }
    pub fn admit_linked(plugin: &'static LinkedPlugin, needs: FakeNeeds) -> Result<Self, Refusal> {
        Self::from_harness(Harness::admit_linked(plugin, needs)?)
    }
    pub fn admit_admitted(image: Admitted, needs: FakeNeeds) -> Result<Self, Refusal> {
        Self::from_harness(Harness::admit_admitted(image, needs)?)
    }
    pub fn from_harness(inner: Harness) -> Result<Self, Refusal> {
        if inner.kind() != KindCode::Store {
            return Err(Refusal::new(
                RefusalCode::Integrity,
                "kind",
                "non-store image",
                "store image",
            ));
        }
        inner
            .registry()
            .set_store_seal(Box::new(|| Box::new(TestKernelSeal)));
        Ok(Self { inner })
    }
    pub fn harness(&self) -> &Harness {
        &self.inner
    }
    pub fn needs(&self) -> &FakeNeeds {
        self.inner.needs()
    }
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.inner.block_on(future)
    }
    pub fn check(&self, case: &StoreCase) -> Result<(), OpenError> {
        let mut spec = self.inner.spec(&case.name, &case.config);
        spec.limits = case.limits;
        self.block_on(self.inner.registry().check(&spec))
    }
    pub fn open(&self, case: &StoreCase) -> Result<StoreHandle, OpenError> {
        let mut spec = self.inner.spec(&case.name, &case.config);
        spec.limits = case.limits;
        self.block_on(self.inner.registry().open_store(&spec))
    }
    /// Inspect a store test's wiping byte value, without exposing a reusable production seal.
    pub fn value_bytes<'a>(&self, value: &'a Secret<Vec<u8>>) -> &'a [u8] {
        value.expose(&TestKernelSeal).as_slice()
    }
    /// Complete live socket accounting. Drop all store handles before this call.
    pub fn finish(&self) -> Result<(), FinishError> {
        #[cfg(feature = "target-sockets")]
        if let Some(target) = self.needs().socket_report() {
            target.finish().map_err(|_| FinishError::Sockets)?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinishError {
    Sockets,
}
impl std::fmt::Display for FinishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "store suite has unfinished socket operations or failures"
        )
    }
}
impl std::error::Error for FinishError {}

/// Run every generic store conformance case over caller-supplied per-case names/configs.
/// The callback receives stable case ids: check, info, 8.1, 8.2, 8.2b, 8.2c, 8.3, 8.4, c13, c20.
/// Each must select an empty dataset. Live endpoints must authorize every returned instance name.
/// No cases can be selected away; a callback error/panic or finish failure fails the suite.
pub fn run_suite(host: &StoreHarness, case: impl FnMut(&str) -> StoreCase) {
    crate::suites::store::run_parameterized(host, case);
}
