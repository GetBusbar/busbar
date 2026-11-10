// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Deterministic auth-kind SDK witness for loader mechanics, without credential policy.

use busbar_contract::abi::auth::AuthPoints;
use busbar_contract::abi::sdk::auth_door::{
    verify_tail, with_tail, Answer, SyncVerifyPlugin, Verdict, VerifyView,
};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::life::Refusal;

pub const NAME: &str = "neutral-auth-witness";

pub struct Witness;

impl SyncVerifyPlugin for Witness {
    fn open_refusing(_: &[u8], _: &[&[u8]]) -> Result<Self, Refusal> {
        Ok(Self)
    }

    fn verify(&self, _: &VerifyView<'_>) -> Answer {
        Verdict::Pass.into()
    }

    fn reload(&self, _: &[u8], _: &[&[u8]]) -> Result<u64, Refusal> {
        Ok(0)
    }
}

busbar_contract::auth_verify_door!(
    Witness,
    with_tail(
        statement(NAME, "1.6.0", 16),
        &verify_tail(0, AuthPoints::HEAD)
    )
);
