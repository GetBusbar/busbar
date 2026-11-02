// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::inbound::SignedIngress;
use busbar_kernel::plane_driver::dispatch::Ingress;
use busbar_kernel::state::App;
use std::sync::Arc;

#[must_use]
pub fn signed_by_dialect() -> SignedIngress {
    Arc::new(|app: &App, path: &str| {
        let ingress = app.planes.ingress_of(path);
        matches!(ingress, Ingress::Fallback(_))
            && busbar_kernel::ingress::protocols::uses_signed_ingress_auth(
                busbar_kernel::ingress::native::envelope_dialect(ingress),
            )
    })
}
