// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Command registration selection from the same immutable seat authority as the request.
use super::*;
use crate::upstreams::{ConfiguredUpstreams, UpstreamDef, Upstreams};

#[derive(Clone)]
pub(super) struct SelectedCommand {
    pub(super) definition: Arc<UpstreamDef>,
}

impl RequestRoutes {
    /// Root lends the actual seat's validated registration table, before publishing its routes.
    pub fn with_registrations(
        mut self,
        registrations: Arc<ConfiguredUpstreams>,
    ) -> Result<Self, AdmissionError> {
        for name in registrations.names() {
            if name.is_empty()
                || name.chars().any(char::is_control)
                || self
                    .catalog
                    .as_ref()
                    .is_some_and(|catalog| catalog.select(name).is_some())
            {
                return Err(AdmissionError::Route);
            }
            let definition = registrations.get(name).ok_or(AdmissionError::Route)?;
            if definition.name.as_ref() != name {
                return Err(AdmissionError::Route);
            }
            if definition.command.is_some()
                && self
                    .registration
                    .as_ref()
                    .is_some_and(|default| default.pool == name)
            {
                // The URL-only default walk cannot be the same actual target as this command.
                return Err(AdmissionError::Route);
            }
        }
        // A consuming builder cannot preserve a seal that was previously minted from this object.
        self.identity = Arc::new(());
        self.registrations = Some(registrations);
        Ok(self)
    }

    /// Read-only route classification. This definition is not an invocation or spawn authority.
    pub fn command_registration(&self, upstream: &str) -> Option<Arc<UpstreamDef>> {
        let definition = self.registrations.as_ref()?.get(upstream)?;
        (definition.command.is_some() && definition.url.is_none()).then_some(definition)
    }
}

impl RequestAllocation {
    /// The retained Task supplied FORWARD + W_UPSTREAM. W_MODEL may not select a different domain.
    /// The upstream passes the same scope rule as a walk; under a selection it must be one of
    /// the selected tuples' own upstreams (K2).
    /// No FarEnd, exchange or synthetic URL is minted for a configured command.
    pub fn registration(
        self,
        routes: &RequestRoutes,
        model: Option<&str>,
        upstream: &str,
    ) -> Result<RequestPoolReceipt, AdmissionError> {
        if model.is_some() {
            return Err(AdmissionError::Route);
        }
        let definition = routes
            .command_registration(upstream)
            .ok_or(AdmissionError::Route)?;
        let selection = self.selection.as_deref();
        if !routes.scope_admits(&self.key, selection, upstream)
            || selection.is_some_and(|selected| !selected.grants_upstream(upstream))
        {
            return Err(AdmissionError::Scope);
        }
        let mut receipt =
            self.resolve(routes, RequestDomain::Registration(upstream.into()), None)?;
        receipt.command = Some(SelectedCommand { definition });
        Ok(receipt)
    }
}

impl RequestPoolReceipt {
    pub fn registered_command(&self) -> Option<&Arc<UpstreamDef>> {
        self.command.as_ref().map(|selected| &selected.definition)
    }
}

impl AdmittedRequest {
    /// Exact selected definition; callers may not reconstruct it from plugin output or a current table.
    pub fn registered_command(&self) -> Option<&Arc<UpstreamDef>> {
        self.command.as_ref().map(|selected| &selected.definition)
    }

    /// Later forwarding must preserve both the selected domain and exact command definition.
    pub fn accepts_forward(
        &self,
        routes: &RequestRoutes,
        model: Option<&str>,
        upstream: Option<&str>,
    ) -> bool {
        if let Some(selected) = self.registered_command() {
            return self.is_live()
                && model.is_none()
                && Arc::ptr_eq(&self.routes, &routes.identity)
                && upstream
                    .and_then(|name| routes.command_registration(name))
                    .is_some_and(|definition| Arc::ptr_eq(selected, &definition));
        }
        self.accepts_route(routes, model)
    }
}
