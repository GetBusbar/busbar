// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::sdk::store::conditional::{
    Decision, Mutation, Predicate, Request, VERSION,
};
use busbar_contract::store_calls::{StoreCalls, StoreFailure};

use super::store_chain::wait_for;

pub(super) fn candidate(predicates: Vec<Predicate>, mutations: Vec<Mutation>) -> Request {
    Request {
        version: VERSION,
        op_id: busbar_kernel::door::op_id(),
        predicates,
        mutations,
    }
}

pub(super) fn decide(calls: &dyn StoreCalls, request: &Request) -> Result<Decision, String> {
    if !calls.supports_record_transaction() {
        return Err(
            "the configured store must support atomic conditional record transactions".into(),
        );
    }
    request.validate().map_err(str::to_string)?;
    let mut unknown = false;
    loop {
        match wait_for(calls.record_transaction(request)) {
            Ok(decision) => return Ok(decision),
            Err(StoreFailure::Failed(_) | StoreFailure::Fault(_)) => unknown = true,
            Err(why) if !unknown => return Err(why.to_string()),
            Err(_) => {}
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}
