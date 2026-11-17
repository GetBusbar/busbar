// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One whole rendered plane answer (status, fields, body) for the open/refusal paths.

use super::*;

pub(super) struct Whole {
    pub(super) status: u32,
    pub(super) fields: HeadFields,
    pub(super) body: Bytes,
}
impl Whole {
    pub(super) fn failed() -> Self {
        Self {
            status: refusal_status(ReasonCode::PlanePanic),
            fields: Vec::new(),
            body: Bytes::new(),
        }
    }
}
impl From<Rendered> for Whole {
    fn from(rendered: Rendered) -> Self {
        Self {
            status: rendered.status,
            fields: rendered.fields,
            body: Bytes::from(rendered.body),
        }
    }
}
