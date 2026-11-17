// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Gather opaque HTTP frames without detaching their retained payload from process custody.

use axum::body::Body;
use bytes::Bytes;
use http_body_util::BodyExt;

use super::process_admission::{CapacityDenied, RequestLease};

#[derive(Debug)]
pub enum GatherError {
    Body(axum::Error),
    TooLarge,
    Capacity(CapacityDenied),
}

/// Independently charge a gathered copy while each opaque source frame still owns its backing.
///
/// A `Bytes` value cannot donate an inaccessible credit, so even one frame is copied only
/// after reserving its destination. Unique decoded chunks instead use `OwnedInput::try_append`.
/// The returned backing keeps the original admission; empty work must additionally retain
/// its request lease through the operation, because an empty `Bytes` need not keep an owner.
///
/// # Errors
/// Keeps body-read failure, the individual message ceiling and aggregate capacity distinct.
pub async fn gather(
    mut body: Body,
    request: &RequestLease,
    max: usize,
) -> Result<Bytes, GatherError> {
    let mut gathered = request
        .adopt_input(Vec::new())
        .map_err(GatherError::Capacity)?;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(GatherError::Body)?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if data.len() > max.saturating_sub(gathered.len()) {
            return Err(GatherError::TooLarge);
        }
        gathered
            .try_extend_from_slice(&data)
            .map_err(GatherError::Capacity)?;
    }
    Ok(gathered.into_bytes())
}

#[cfg(test)]
#[path = "tests/input_body_tests.rs"]
mod tests;
