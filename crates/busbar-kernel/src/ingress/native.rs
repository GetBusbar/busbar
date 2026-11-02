// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::http::StatusCode;
use axum::response::Response;

use crate::plane_driver::dispatch::Ingress;

pub fn envelope_dialect(ingress: Ingress) -> &'static str {
    ingress
        .shaping_wire_format()
        .or_else(crate::ingress::protocols::residual_default_dialect)
        .unwrap_or("")
}

pub(crate) fn native_error(
    ingress: Ingress,
    status: StatusCode,
    kind: &str,
    message: &str,
) -> Response {
    match ingress {
        Ingress::Mounted(_) => crate::ingress::jsonrpc::transport_refusal(status, message),

        Ingress::Fallback(_) => {
            crate::ingress::ingress_error(envelope_dialect(ingress), status, kind, message)
        }
    }
}
