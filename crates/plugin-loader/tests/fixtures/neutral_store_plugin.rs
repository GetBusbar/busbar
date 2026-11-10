// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Deterministic STORE crossing witness; no storage engine or persistence policy.
use busbar_contract::abi::sdk::store::v4::backend::{Backend, Committed};
use busbar_contract::abi::sdk::store::{Op, Step};
use busbar_contract::persistence::{self as owned, lifecycle};
type Host = busbar_contract::abi::sdk::conn::Host<busbar_contract::plugin::markers::StoreKind>;

busbar_contract::own_seal!(Own);
struct Witness {
    owner: Own,
}
impl Backend for Witness {
    type Owner = Own;
    fn owner(&self) -> &Own {
        &self.owner
    }
    fn input_budget(&self) -> usize {
        1_048_576
    }
    fn validate(_: &[u8]) -> Result<(), String> {
        Ok(())
    }
    fn open(_: &[u8], _: &[&[u8]], _: Option<Host>) -> Result<Self, String> {
        Ok(Self { owner: Own::here() })
    }
    fn connect(&self, _: &mut Op<'_>) -> Step<Result<(), String>> {
        Step::Ready(Ok(()))
    }
    fn connect_prepared(
        &self,
        _: &mut Op<'_>,
        _: &lifecycle::OpenBinding,
    ) -> Step<Result<(), String>> {
        Step::Ready(Err("witness does not prepare storage".into()))
    }
    fn bootstrap(
        &self,
        _: &mut Op<'_>,
        _: &lifecycle::Request<Own>,
    ) -> Step<Result<lifecycle::Response<Own>, lifecycle::Error>> {
        Step::Ready(Err(lifecycle::Error::MissingCapability))
    }
    fn info(&self) -> owned::BackendInfo {
        owned::BackendInfo {
            dataset: owned::DatasetId([1; 16]),
            atomic_domain: [2; 16],
            clock_authority: [3; 16],
            physical_version: 1,
            durability: owned::Durability::Ephemeral,
        }
    }
    fn read(
        &self,
        _: &mut Op<'_>,
        _: &owned::Read,
    ) -> Step<Result<owned::ReadResult<Own>, owned::Failure>> {
        Step::Ready(Err(owned::Failure::Refused))
    }
    fn scan(
        &self,
        _: &mut Op<'_>,
        _: &owned::Scan,
    ) -> Step<Result<owned::Page<Own>, owned::Failure>> {
        Step::Ready(Err(owned::Failure::Refused))
    }
    fn commit(
        &self,
        _: &mut Op<'_>,
        _: &owned::PreparedCandidate<Own>,
    ) -> Step<Result<Committed<Own>, owned::Failure>> {
        Step::Ready(Err(owned::Failure::Refused))
    }
    fn clock(
        &self,
        _: &mut Op<'_>,
        _: owned::DatasetId,
    ) -> Step<Result<owned::ClockObservation, owned::Failure>> {
        Step::Ready(Ok(owned::ClockObservation {
            authority: self.info().clock_authority,
            unix_seconds: 41,
        }))
    }
}
busbar_contract::store_v4_door!(Witness, "neutral-store-witness", "1.6.0", 1024);
