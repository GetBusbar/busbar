// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! An owned, non-pooled session over the existing explicit socket host target.

use super::{
    InstanceLimits, KindCode, NeedErr, OpenNeed, Security, SocketTargets, TlsMode, TrustSource,
};
use busbar_plugin_abi::host_side::caller::{next_chain, CallStack, Caller};
use std::sync::Arc;
use std::time::Instant;

/// Explicit host-target identity. This is not a production caller or kernel seal.
/// Transport budgets come from [`super::Limits`], not this identity's `limits` metadata.
pub struct SocketCaller {
    pub plugin: String,
    pub kind: KindCode,
    pub name: String,
    pub limits: InstanceLimits,
}

/// One connection on a dedicated host target, driven entirely on the caller's runtime.
///
/// Drop closes the physical connection without a protocol exchange or pool reuse. The caller
/// must keep its runtime alive across open, I/O and drop, then assert [`SocketTargets::finish`]
/// on the retained [`Self::report`]. This models host-target I/O, not kernel policy coverage.
pub struct SocketSession {
    targets: Arc<SocketTargets>,
    identity: SocketCaller,
    instance: u64,
    chain: u64,
    deadline: Instant,
    closed: bool,
}

const CONNECTION: u64 = 1;

impl SocketSession {
    /// Consume exactly one configured target. TLS requires explicit CA roots; profiles requiring
    /// a binder or client identity are refused. Plaintext must be configured explicitly.
    pub async fn open(
        targets: SocketTargets,
        caller: SocketCaller,
        deadline: Instant,
        request: OpenNeed<'_>,
    ) -> Result<Self, NeedErr> {
        Self::open_shared(Arc::new(targets), caller, deadline, request).await
    }

    // Internal tests retain the report to observe failed/cancelled opening. Public callers
    // consume the target once, so it cannot be shared with a registry or another session.
    pub(super) async fn open_shared(
        targets: Arc<SocketTargets>,
        caller: SocketCaller,
        deadline: Instant,
        request: OpenNeed<'_>,
    ) -> Result<Self, NeedErr> {
        if caller.plugin.is_empty() || caller.name.is_empty() || targets.targets.len() != 1 {
            return Err(NeedErr::Denied);
        }
        if Instant::now() >= deadline {
            return Err(NeedErr::Timeout);
        }
        if !targets.configured(&caller.name, request.dest) {
            return Err(NeedErr::Denied);
        }
        if targets.targets.values().any(|security| {
            matches!(security, Security::Tls(profile)
                if !matches!(profile.trust, TrustSource::Explicit { .. }) || profile.client.is_some())
        }) {
            return Err(NeedErr::Denied);
        }
        let mut session = Self {
            targets,
            identity: caller,
            instance: next_chain(),
            chain: next_chain(),
            deadline,
            closed: true,
        };
        {
            let caller = session.caller();
            session
                .targets
                .prepare(&caller, request, CONNECTION, CONNECTION)?
                .run()
                .await?;
        }
        session.closed = false;
        Ok(session)
    }

    /// Read into the caller's existing storage. EOF closes the session and returns zero.
    pub async fn read_into(&mut self, out: &mut [u8]) -> Result<usize, NeedErr> {
        let operation = self.operation()?;
        let max = u32::try_from(out.len()).map_err(|_| NeedErr::Limit)?;
        let answer = {
            let caller = operation.session.caller();
            operation
                .session
                .targets
                .read(&caller, CONNECTION, max)
                .await?
        };
        let n = answer.bytes.len();
        out.get_mut(..n)
            .ok_or(NeedErr::Limit)?
            .copy_from_slice(answer.bytes.as_slice());
        if !answer.eof {
            operation.complete();
        }
        Ok(n)
    }

    /// Write all bytes, or close non-reusably and return the original I/O failure.
    pub async fn write_all(&mut self, bytes: &[u8]) -> Result<(), NeedErr> {
        let operation = self.operation()?;
        let written = {
            let caller = operation.session.caller();
            operation
                .session
                .targets
                .write(&caller, CONNECTION, bytes)
                .await?
        };
        if written != u64::try_from(bytes.len()).map_err(|_| NeedErr::Limit)? {
            return Err(NeedErr::Closed);
        }
        operation.complete();
        Ok(())
    }

    /// Upgrade using the existing target's verified TLS path and exact OPEN profile.
    pub async fn starttls(&mut self, tls: TlsMode<'_>) -> Result<(), NeedErr> {
        let operation = self.operation()?;
        {
            let caller = operation.session.caller();
            operation
                .session
                .targets
                .starttls(&caller, CONNECTION, tls)
                .await?;
        }
        operation.complete();
        Ok(())
    }

    /// Retain the existing lifecycle accounting without exposing caller identities.
    pub fn report(&self) -> Arc<SocketTargets> {
        Arc::clone(&self.targets)
    }

    /// Idempotently close the physical connection, without reset, rollback or pool reuse.
    pub fn close(&mut self) {
        self.closed = true;
        self.targets.close(&self.caller(), CONNECTION, false);
    }

    fn caller(&self) -> Caller<'_> {
        Caller {
            plugin: &self.identity.plugin,
            kind: self.identity.kind,
            name: &self.identity.name,
            instance: self.instance,
            slot: 0,
            chain: self.chain,
            deadline: self.deadline,
            stack: CallStack::default(),
            out_of_process: false,
            limits: self.identity.limits,
        }
    }

    fn operation(&mut self) -> Result<Operation<'_>, NeedErr> {
        if self.closed {
            return Err(NeedErr::Closed);
        }
        // A polled operation owns the session until successful completion. Cancelling its
        // future leaves both the wrapper and the underlying socket terminal.
        self.closed = true;
        Ok(Operation {
            session: self,
            complete: false,
        })
    }
}

impl Drop for SocketSession {
    fn drop(&mut self) {
        self.close();
    }
}

struct Operation<'a> {
    session: &'a mut SocketSession,
    complete: bool,
}
impl Operation<'_> {
    fn complete(mut self) {
        self.session.closed = false;
        self.complete = true;
    }
}
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.session.close();
        }
    }
}
