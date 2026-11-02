// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;

pub struct ArrivalCtx(Box<dyn std::any::Any + Send + Sync>);

impl ArrivalCtx {
    pub fn new<T: std::any::Any + Send + Sync>(payload: T) -> Self {
        ArrivalCtx(Box::new(payload))
    }

    pub fn downcast_ref<T: std::any::Any>(&self) -> Option<&T> {
        self.0.downcast_ref::<T>()
    }
}

pub struct ArrivalPayload {
    pub host: Arc<dyn crate::plane_driver::EngineHost>,

    pub gov: busbar_contract::records::PlaneRequestCtx,

    pub caller_token: Option<crate::auth::CallerCredential>,
}

pub trait ArrivalHost: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    fn finish_rejected(
        &self,
        ctx: &ArrivalCtx,
        proto: &str,
        pool: &str,
        started: Instant,
        charged_at: u64,
        resp: Response,
    ) -> Response;

    fn ingress_error(&self, proto: &str, status: StatusCode, kind: &str, message: &str)
        -> Response;

    fn envelope_dialect(&self, ctx: &ArrivalCtx, path: &str) -> &'static str;

    fn fallback_not_found(
        &self,
        ctx: &ArrivalCtx,
        path: &str,
        status: StatusCode,
        err_type: &str,
        message: &str,
    ) -> Response;

    fn percent_decode(&self, s: &str) -> String;

    fn kind_not_found(&self) -> &'static str;

    fn kind_invalid_request(&self) -> &'static str;

    fn err_type_not_found(&self) -> &'static str;
}

pub struct Arrival {
    pub host: Arc<dyn ArrivalHost>,

    pub ctx: ArrivalCtx,

    pub path: String,

    pub model_hint: Option<String>,

    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Bytes,
}
