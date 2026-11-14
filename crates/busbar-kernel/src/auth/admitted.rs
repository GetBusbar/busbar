// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The shared completion of a transport's verified admission. No route is rematched here.

use super::*;

/// Request context held by the host after admission, pinned to its admitting generation.
pub struct AdmittedContext {
    pub app: std::sync::Arc<App>,
    pub head: crate::inbound::Head,
    pub principal: AuthPrincipal,
    pub gov: crate::governance::GovCtx,
    pub consumed: ConsumedCredentials,
    pub consumed_fields: Vec<(String, String)>,
}

#[derive(Debug)]
pub enum AdmittedRefusal {
    SenderConstraint,
    Audience(&'static str),
    Identity(IdentityRefusal),
}

/// Complete the same credential, sender constraint, ticket, identity and replay checks for
/// both neutral data requests and the HTTP operator adapter's admitted requests.
pub async fn admitted_context(
    request: &crate::inbound::RequestAdmission,
) -> Result<AdmittedContext, AdmittedRefusal> {
    let result = complete_context(request).await;
    if let Err(refusal) = &result {
        use busbar_contract::caps::{ReasonCode, StepName};
        let (step, reason) = match refusal {
            AdmittedRefusal::Identity(IdentityRefusal::NoGrant) => {
                (StepName::Approve, ReasonCode::ScopeDenied)
            }
            _ => (StepName::Authenticate, ReasonCode::Unauthenticated),
        };
        request.refuse(step, reason);
    }
    result
}

async fn complete_context(
    request: &crate::inbound::RequestAdmission,
) -> Result<AdmittedContext, AdmittedRefusal> {
    let app = request.app();
    let mut head = request.head().clone();
    if matches!(request.selected_line().auth, crate::guest::LineAuth::None) {
        if !request.claim_replay().await {
            return Err(AdmittedRefusal::Identity(IdentityRefusal::Denied));
        }
        return Ok(AdmittedContext {
            app,
            head,
            principal: AuthPrincipal(None),
            gov: crate::governance::GovCtx::default(),
            consumed: ConsumedCredentials::default(),
            consumed_fields: Vec::new(),
        });
    }

    // HTTP-compatible credential carriers are an auth concern, not the plane data envelope.
    // Fields that are not carriers remain opaque in `head`, including non-HTTP field names.
    let headers = request.original_headers();
    let client_token = request.client_token();
    let mut read = None;
    let (client_token, proven) = match dpop::judge_method(
        &app,
        &request.inner.original.method,
        &request.inner.original.target,
        headers,
        client_token,
        &mut read,
    )
    .await
    {
        dpop::SenderConstraint::Unconstrained => {
            (client_token.map(std::borrow::Cow::Borrowed), false)
        }
        dpop::SenderConstraint::Proven(token) => (Some(std::borrow::Cow::Owned(token)), true),
        dpop::SenderConstraint::Refused => return Err(AdmittedRefusal::SenderConstraint),
    };
    let mut consumed = gate_consumed(&app, false, proven);
    consumed.caller = verified_caller_credential(
        Some(request.inner.credential.as_ref()),
        client_token.as_deref(),
    );
    consumed.carry(
        &request
            .inner
            .strips
            .iter()
            .filter(|strip| strip.place == StripPlace::Field)
            .filter_map(|strip| HeaderName::from_bytes(strip.name.as_bytes()).ok())
            .collect::<Vec<_>>(),
    );
    let ticketed = claimed_ticket_verdict(
        request.inner.signed,
        app.auth.keys_in_chain,
        request.ticket_prefix(),
        client_token.as_deref(),
        app.governance.as_ref(),
        busbar_kernel::store::now(),
        app.root_rules.as_ref(),
    )
    .await
    .map_err(|()| AdmittedRefusal::Identity(IdentityRefusal::Denied))?;
    let verdict = if let Some((verdict, record, ticket)) = ticketed {
        consumed.ticket = Some(record);
        consumed.host_ticket_admission = ticket;
        verdict
    } else {
        if !request.inner.signed {
            if let (Some(admission), Some(token)) =
                (request.plane_admission(), client_token.as_deref())
            {
                match read
                    .get_or_insert_with(|| audience::Bearer::read(token))
                    .binding(&admission.audience)
                {
                    audience::Binding::Deferred | audience::Binding::Bound => {}
                    audience::Binding::Mismatch => {
                        return Err(AdmittedRefusal::Audience(audience::MISMATCH_DESCRIPTION))
                    }
                    audience::Binding::Opaque => {
                        return Err(AdmittedRefusal::Audience(audience::OPAQUE_DESCRIPTION))
                    }
                }
            }
        }
        request.verdict()
    };
    let (principal, gov) =
        resolve_data_plane_identity(&app, verdict).map_err(AdmittedRefusal::Identity)?;
    request.principal(
        gov.key()
            .map_or_else(|| principal.actor_id(), |key| key.id.as_str()),
    );
    if !request.claim_replay().await {
        return Err(AdmittedRefusal::Identity(IdentityRefusal::Denied));
    }
    let consumed_fields = ConsumedCredentials::fields_of(Some(&consumed), headers);
    consumed.strip_neutral(&mut head);
    Ok(AdmittedContext {
        app,
        head,
        principal,
        gov,
        consumed,
        consumed_fields,
    })
}

impl AdmittedRefusal {
    /// The declared resource's OAuth challenge, if this admission has one. Other refusals
    /// remain the selected plane's rendering; no fallback dialect is guessed here.
    pub fn challenge(
        &self,
        request: &crate::inbound::RequestAdmission,
    ) -> Option<crate::plane_driver::Rendered> {
        let admission = request.plane_admission()?;
        let (error, description) = match self {
            Self::SenderConstraint => (challenge::ChallengeError::InvalidToken,
                "A DPoP-bound access token needs its DPoP proof (RFC 9449), and this one did not verify."),
            Self::Audience(description) => (challenge::ChallengeError::InvalidToken, *description),
            Self::Identity(IdentityRefusal::NoGrant) => (challenge::ChallengeError::InsufficientScope,
                "The authenticated principal carries no grant on this resource."),
            Self::Identity(IdentityRefusal::Denied) => {
                let app = request.app();
                let present = request.client_token().is_some()
                    || (app.oauth_as.is_some()
                        && dpop::dpop_credential(request.original_headers()).is_some());
                (if present { challenge::ChallengeError::InvalidToken } else { challenge::ChallengeError::Absent },
                 "Authentication is required for this resource.")
            }
        };
        Some(challenge::render(
            error,
            &admission.resource_metadata,
            description,
            None,
        ))
    }
}

impl crate::inbound::RequestAdmission {
    /// Project the first-hand identity through the pinned admin bindings and provider cap.
    /// This never verifies credentials again or spends replay before the admin approve step.
    #[must_use]
    pub fn admin_verdict(&self) -> super::AdminVerdict {
        let app = self.app();
        if self.inner.admitted.as_ref().is_some_and(|admitted| {
            super::admin_sender_constraint::downgraded(
                &app,
                &admitted.provider,
                self.original_headers(),
            )
        }) {
            return super::AdminVerdict {
                door: super::AdminDoor::Denied,
                claim: None,
            };
        }
        let cap = self
            .inner
            .admitted
            .as_ref()
            .and_then(|admitted| super::module_admin_scope_cap(&app, &admitted.provider));
        super::AdminVerdict {
            door: super::admin_door_of(&app, self.verdict(), cap),
            // The host admin bridge claims through claim_admin_replay after approve.
            claim: None,
        }
    }
}
