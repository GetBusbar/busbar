// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A core route that requires a key (`RouteAuth::Key`): `/stats`, and an export or hook plugin's
//! own keyed route (a metrics scrape). The data chain verifies the caller on the head; the handler
//! is given the verified caller's key and filters its answer by it; no unit is opened. A caller
//! that is not verified receives the one unverified answer, as on every route.

use std::sync::Arc;

use axum::response::Response;
use busbar_kernel::auth::native_data::{verify_core_key, withheld_carriers};
use busbar_kernel::inbound::native::{
    CompletingPhysicalRequest, PhysicalKeyExecution, PhysicalKeyRefusal,
};

use super::{answer, InputError};
use crate::root::min3_physical::NativeSlot;

pub(super) enum KeyAnswered {
    Served(Response, Arc<PhysicalKeyExecution>),
    Refused(Response, PhysicalKeyRefusal),
}

pub(super) async fn prepare(
    request: CompletingPhysicalRequest,
    slot: Option<Arc<NativeSlot>>,
) -> Result<KeyAnswered, InputError> {
    let binding = request.binding().clone();
    // No data chain on this listener: nobody could be verified, so nobody is served.
    let Some(chain) = slot.and_then(|slot| slot.data_chain()) else {
        let response = answer::unverified(&binding, &[], None)?;
        let refusal =
            request.refuse_core_key(busbar_kernel::auth::native_data::DataRefused::Credential)?;
        return Ok(KeyAnswered::Refused(response, refusal));
    };
    let deadline = binding.deadline().ok_or(InputError::Invalid)?;
    let mono_ns = binding.mono_ns().ok_or(InputError::Invalid)?;
    let verified = verify_core_key(
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
    match verified {
        Ok(authorization) => {
            let owner = Arc::new(request.complete_core_key(authorization)?);
            let response = owner.http_response().await?;
            Ok(KeyAnswered::Served(response, owner))
        }
        Err(reason) => {
            let carriers = withheld_carriers(&chain, None);
            let refusal = reason
                .refusal(answer::presented(&binding, &carriers))
                .ok_or(InputError::Invalid)?;
            let response = answer::core(&binding, refusal, reason.after_verification(), "", None)?;
            Ok(KeyAnswered::Refused(
                response,
                request.refuse_core_key(reason)?,
            ))
        }
    }
}
