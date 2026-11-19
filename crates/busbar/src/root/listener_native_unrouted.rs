// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A request no mounted route matched (an unknown path, a wrong method, a declared route this
//! configuration does not mount). The data chain judges the caller: a verified caller is told the
//! truth (404, or 405 with `Allow`); anyone else receives the one unverified answer, identical to
//! a real route's, so nothing about the route table is learned without a valid credential.

use std::sync::Arc;

use axum::response::Response;
use busbar_kernel::auth::admission_table::{decide, Decision, Facts, Refusal, Step, Target};
use busbar_kernel::auth::native_data::{judge_unrouted, withheld_carriers};
use busbar_kernel::inbound::native::{CompletingPhysicalRequest, PhysicalRefusal};

use super::{answer, InputError};
use crate::root::min3_physical::NativeSlot;

/// The methods the request's path does accept on this listener, when some route's path matches
/// and no route's method does; `None` for a path no route has.
fn allowed_methods(slot: &NativeSlot, path: &str) -> Option<u32> {
    let methods = slot.methods_at(path);
    (methods != 0).then_some(methods)
}

pub(super) async fn prepare(
    request: CompletingPhysicalRequest,
    slot: Option<Arc<NativeSlot>>,
) -> Result<(Response, PhysicalRefusal), InputError> {
    let binding = request.binding().clone();
    // A listener with no data chain (no slot selected for this app) has nobody who could be
    // verified: every caller receives the one unverified answer.
    let Some((slot, chain)) = slot.and_then(|slot| {
        let chain = slot.data_chain()?;
        Some((slot, chain))
    }) else {
        let response = answer::unverified(&binding, &[], None)?;
        return Ok((response, request.refuse_unrouted()?));
    };
    let carriers = withheld_carriers(&chain, None);
    let target = match allowed_methods(&slot, path_of(&binding.head().target)) {
        Some(allow) => Target::WrongMethod { allow },
        None => Target::NoRoute,
    };
    let mut facts = Facts::arrived(answer::presented(&binding, &carriers), false);
    let deadline = binding.deadline().ok_or(InputError::Invalid)?;
    let mono_ns = binding.mono_ns().ok_or(InputError::Invalid)?;
    // The decision asks for the chain's judgement once; both of its facts come from one run.
    let refusal = loop {
        match decide(target, &facts) {
            Decision::Run(Step::Verify | Step::Policy) if facts.verified.is_none() => {
                let (verified, policy) = judge_unrouted(
                    binding.app(),
                    &chain,
                    &binding,
                    busbar_ports::CallCx {
                        deadline,
                        request_id: binding.invocation().request_id().get(),
                        stack: Default::default(),
                        mono_ns,
                    },
                )
                .await;
                facts.verified = verified;
                facts.policy = policy;
            }
            Decision::Refuse { refusal, verified } => break (refusal, verified),
            // No sequence serves a request with no route, and no step beyond the chain's exists
            // for one: anything else is the engine's fault and is answered as not verified.
            Decision::Run(_) | Decision::Serve(_) => {
                break (
                    Refusal::Unverified {
                        presented: facts.presented,
                    },
                    false,
                )
            }
        }
    };
    let (refusal, verified) = refusal;
    let response = answer::core(&binding, refusal, verified, "", None)?;
    Ok((response, request.refuse_unrouted()?))
}

/// The path of a request target: what precedes its query.
fn path_of(target: &str) -> &str {
    target.split_once('?').map_or(target, |(path, _)| path)
}
