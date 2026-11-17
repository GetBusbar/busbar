// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Read current routing policy without altering the original request admission.
use super::*;
use crate::config::OnExhaustedCfg;
use crate::plane_driver::port_egress::SelectedWalkAttempt;

impl RequestRoutes {
    /// The caller lends the actual current seat under its publication guard and supplies the
    /// current key validated from this request's original credential. Ingress/target provenance
    /// is checked by that caller; this check cannot grant a request, member or monetary admission.
    pub(crate) fn allows_current_selection(
        &self,
        request: &AdmittedRequest,
        selection: &SelectedWalkAttempt,
        current_key: &VirtualKey,
    ) -> bool {
        request.accepts_walk(selection.walk())
            && self.allows_current_pair(
                request,
                current_key,
                selection.pool(),
                selection.qualified_member(),
            )
    }

    pub(super) fn allows_current_pair(
        &self,
        request: &AdmittedRequest,
        current_key: &VirtualKey,
        selected_pool: &str,
        member: &str,
    ) -> bool {
        if !request.is_live()
            || request.context().instance() != self.instance
            || !request
                .member_grants()
                .get(selected_pool)
                .is_some_and(|members| members.iter().any(|m| m == member))
        {
            return false;
        }
        let selector = match request.domain() {
            RequestDomain::NamedPool(name)
            | RequestDomain::DirectModel(name)
            | RequestDomain::Registration(name) => name,
            RequestDomain::Local => return false,
        };
        let Ok((domain, initial)) = self.resolve(Some(selector)) else {
            return false;
        };
        if &domain != request.domain() {
            return false;
        }
        let grants = self.member_grants(current_key);
        if !grants
            .get(selected_pool)
            .is_some_and(|members| members.iter().any(|m| m == member))
        {
            return false;
        }
        if matches!(domain, RequestDomain::Registration(_)) {
            return selected_pool == initial;
        }
        let Some(catalog) = &self.catalog else {
            return false;
        };
        let mut at = initial.as_str();
        // The frozen catalog bounds traversal; a cycle or a missing intermediary refuses.
        for _ in 0..catalog.pools().len() {
            if !grants.contains_key(at) {
                return false;
            }
            let Some(pool) = catalog.pools().get(at) else {
                return false;
            };
            if at == selected_pool {
                return catalog.target(at, member).is_some();
            }
            let Some(OnExhaustedCfg::FallbackPool(next)) = &pool.config.on_exhausted else {
                return false;
            };
            let Some(next) = catalog.select(next) else {
                return false;
            };
            if !catalog
                .pools()
                .get(next)
                .is_some_and(|p| matches!(p.kind, RouteKind::NamedPool(_)))
            {
                return false;
            }
            at = next;
        }
        false
    }
}
