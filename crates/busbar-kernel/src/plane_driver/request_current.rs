// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Read current routing policy without altering the original request admission.
use super::*;
use crate::config::OnExhaustedCfg;
use crate::plane_driver::port_egress::SelectedWalkAttempt;

impl RequestRoutes {
    /// Read-only candidate routing check. The current-policy caller separately validates the
    /// original credential/route and actual target definition; this never admits a dispatch.
    pub(crate) fn allows_current_candidate(
        &self,
        request: &AdmittedRequest,
        candidate: &crate::plane_driver::port_upstream::Candidate,
        current_key: &VirtualKey,
    ) -> bool {
        self.allows_current_pair(
            request,
            current_key,
            &candidate.pool,
            &candidate.qualified_member,
        )
    }

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
                .is_some_and(|members| members.iter().any(|m| *m == member))
        {
            return false;
        }
        let Some(member_name) = member
            .strip_prefix(self.instance.as_str())
            .and_then(|suffix| suffix.strip_prefix(PLANE_LANE_SEP))
        else {
            return false;
        };
        // The admission rule again, on the current key and the request's own selection:
        // a key narrowed after admission loses the walk (K2, PM ruling 1 on #462).
        let allowed =
            |name: &str| self.scope_admits(current_key, request.selection.as_deref(), name);
        if let RequestDomain::Registration(name) = request.domain() {
            return self.registration.as_ref().is_some_and(|registration| {
                &registration.pool == name
                    && selected_pool == registration.pool
                    && allowed(name)
                    && registration
                        .members
                        .iter()
                        .any(|m| &*m.upstream == member_name)
            });
        }
        if let RequestDomain::NamedPool(name) = request.domain() {
            if self.section_pools.contains_key(name) {
                // A section walk reaches its own pool and that pool's one fallback; the current
                // key must still hold both and the selected member (#108).
                let selection = request.selection.as_deref();
                let fallback = self
                    .section_pools
                    .get(name)
                    .and_then(|pool| pool.fallback.as_deref());
                return (name.as_str() == selected_pool || fallback == Some(selected_pool))
                    && self.section_walk_admits(current_key, selection, name)
                    && self.section_member_admits(
                        current_key,
                        selection,
                        selected_pool,
                        member_name,
                    );
            }
        }
        let Some(catalog) = &self.catalog else {
            return false;
        };
        let selector = match request.domain() {
            RequestDomain::NamedPool(name) | RequestDomain::DirectModel(name) => name,
            _ => return false,
        };
        let Some(initial) = catalog.select(selector) else {
            return false;
        };
        let Some(pool) = catalog.pools().get(initial) else {
            return false;
        };
        if !matches!((request.domain(), &pool.kind),
            (RequestDomain::NamedPool(a), RouteKind::NamedPool(b)) |
            (RequestDomain::DirectModel(a), RouteKind::DirectModel(b)) if a == b)
        {
            return false;
        }
        let mut at = initial;
        // The frozen catalog bounds traversal; a cycle or a missing intermediary refuses.
        for _ in 0..catalog.pools().len() {
            let Some(pool) = catalog.pools().get(at) else {
                return false;
            };
            let name = match &pool.kind {
                RouteKind::NamedPool(name) | RouteKind::DirectModel(name) => name,
            };
            if !allowed(name) {
                return false;
            }
            if at == selected_pool {
                return pool.config.members.iter().any(|m| m.name() == member_name);
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
                .is_some_and(|p| matches!(&p.kind, RouteKind::NamedPool(_)))
            {
                return false;
            }
            at = next;
        }
        false
    }
}
