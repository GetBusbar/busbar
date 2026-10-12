// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TEST STAND-INS ONLY: an in-process [`AuthModule`] as a chain position's [`AuthCalls`]. A test
//! build composes an auth chain from in-process modules without a loaded plugin; every plugin a
//! shipped build opens comes through the auth axis on the auth kind's memory ABI (THE DESIGN §11.6).
//! The module's `authenticate` is made on the caller's thread and answered on the spot.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use busbar_contract::abi::auth::FACT_CACHEABLE;
use busbar_contract::auth::{AuthModule, AuthVerdict};
use busbar_contract::auth_calls::{
    AuthCalls, Verified, VerifiedIdentity, VerifyAnswer, VerifyRequest, Verifying,
};

/// An in-process test module as [`AuthCalls`].
pub struct InProcessAuth {
    module: Arc<dyn AuthModule>,
    name: String,
    facts: u32,
}

impl std::fmt::Debug for InProcessAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InProcessAuth")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl InProcessAuth {
    /// The adapter over `module`.
    #[must_use]
    pub fn new(module: Box<dyn AuthModule>) -> Self {
        let facts = if module.cacheable() {
            FACT_CACHEABLE
        } else {
            0
        };
        Self {
            name: module.name().to_string(),
            module: Arc::from(module),
            facts,
        }
    }
}

/// A module's verdict as the chain reads it.
fn verified(v: AuthVerdict) -> Verified {
    match v {
        AuthVerdict::Identify(p) => Verified::Identity(VerifiedIdentity {
            subject: p.id,
            name: p.name,
            groups: p.roles,
            ttl_secs: p.ttl_secs,
            ..VerifiedIdentity::default()
        }),
        AuthVerdict::Reject => Verified::Reject,
        AuthVerdict::Pass => Verified::Pass,
    }
}

impl AuthCalls for InProcessAuth {
    fn name(&self) -> &str {
        &self.name
    }

    fn facts(&self) -> u32 {
        self.facts
    }

    fn verify_now(&self, request: &VerifyRequest) -> Option<VerifyAnswer> {
        let credential = request
            .credential
            .as_ref()
            .map(|c| String::from_utf8_lossy(c.expose_secret()).into_owned());
        Some(verified(self.module.authenticate(credential.as_deref())).into())
    }

    fn verify(&self, request: VerifyRequest) -> Box<dyn Verifying> {
        Box::new(Answered(self.verify_now(&request)))
    }

    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}

/// A verify answered on the spot.
struct Answered(Option<VerifyAnswer>);

impl Future for Answered {
    type Output = VerifyAnswer;
    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<VerifyAnswer> {
        Poll::Ready(self.0.take().unwrap_or_else(|| Verified::Failed.into()))
    }
}

impl Verifying for Answered {
    fn settled(&mut self) -> Option<VerifyAnswer> {
        let mut cx = Context::from_waker(Waker::noop());
        match Pin::new(self).poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }
}
