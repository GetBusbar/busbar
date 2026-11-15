// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Refusal mapping: the one place a refusal crosses kinds, generic codes and core's own text (IF §12.15). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-K8D fills it.

/// Encoded with `plane::encode_refusal` (§8.8).
pub struct ClientRefusal {
    pub status: u16,
    pub code: u32,
    pub text: std::borrow::Cow<'static, str>,
}
pub trait RefusalMap: Send + Sync + 'static {
    // W0-ABI: IF hole, sent to the lead designer. The IF's four methods are
    //   fn from_auth(&self, route: u32, kind_code: u32) -> ClientRefusal;
    //   fn from_hook(&self, route: u32, hook: &str, reject_status: Option<u16>, message: Option<&str>) -> ClientRefusal;
    //   fn from_core(&self, route: u32, code: u32) -> ClientRefusal;
    //   fn from_port(&self, route: u32, e: &PortError) -> ClientRefusal;
    // A `from_*` trait method taking `&self` trips clippy::wrong_self_convention (style, denied in CI) on the trait
    // declaration, and no `#[allow]` is permitted; `from_port` also names `PortError`, a busbar-plugin-loader type
    // (IF §11.3) the kernel cannot reach in wave 0. W1-K8D adds the methods under the names the lead rules.
}
