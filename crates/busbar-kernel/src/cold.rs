// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COLD MODULE (LINT-RULES LR-167): the cold code the kernel's request-path modules need,
//! called out of line: refusal text, spelled only when a request, a unit or a definition is
//! refused, and the first-sight paths that key a name once and then share it. Every fn is
//! `#[cold]` or `#[inline(never)]`; none holds a loop or sweeps request data (BP17). Each section
//! is named for the request-path module it serves.

// --- plane_driver ---

impl crate::plane_driver::DriverConfig {
    /// The status a refusal renders under: the plane's own row for its dialect and reason, else its
    /// any-dialect row, else the kernel's choice. Looked up only when a unit is refused.
    #[cold]
    pub fn status(&self, dialect: u32, reason: busbar_contract::caps::ReasonCode) -> u32 {
        use busbar_contract::abi::plane::{reason_code, REFUSAL_ANY_DIALECT};
        let code = reason_code(reason);
        let row = |d: u32| {
            self.refusal_statuses
                .iter()
                .find(|r| r.dialect == d && r.reason == code)
                .map(|r| r.status)
        };
        row(dialect)
            .or_else(|| row(REFUSAL_ANY_DIALECT))
            .unwrap_or_else(|| (self.status_of)(reason))
    }
}

/// `plane_driver`: the audit resource of a settled unit whose provider's final usage went unbilled.
#[cold]
pub(crate) fn usage_unread_resource(unit: u64, reason: &str) -> String {
    format!("unit:{unit} reason:{reason}")
}

/// `plane_driver`: one span of a plane's arena, copied out once into a rendered refusal's (or a
/// catalog's) owned head; a span outside the arena is empty.
#[inline(never)]
pub(crate) fn rendered_span(
    arena: &[u8],
    s: busbar_contract::abi::mechanism::call::Span,
) -> Vec<u8> {
    let start = s.offset as usize;
    arena
        .get(start..start.saturating_add(s.len as usize))
        .unwrap_or_default()
        .to_vec()
}

/// `plane_driver`: bytes as owned text, lossily, for the DEBUG `request finished` summary only.
#[cold]
pub(crate) fn lossy_owned(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// `plane_driver`: a rendered refusal's body as the frame its encode answers with.
#[cold]
pub(crate) fn refusal_frame(body: &[u8]) -> std::sync::Arc<[u8]> {
    std::sync::Arc::from(body)
}

/// `plane_driver::route`: the opt-in transparency fields naming the hook policy that ordered the
/// walk and the member that answered.
#[cold]
pub(crate) fn route_policy_fields(
    fields: &mut crate::plane_driver::HeadFields,
    policy: &str,
    member: &[u8],
) {
    use crate::plane_driver::{HDR_ROUTE_POLICY, HDR_ROUTE_TARGET};
    fields.push((
        HDR_ROUTE_POLICY.as_bytes().to_vec(),
        policy.as_bytes().to_vec(),
    ));
    fields.push((HDR_ROUTE_TARGET.as_bytes().to_vec(), member.to_vec()));
}
