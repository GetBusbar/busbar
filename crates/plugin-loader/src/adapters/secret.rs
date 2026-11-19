// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The secret adapter: `SecretPort` over the secret kind's `Proxy` (IF §11.3, §8.2). One async method: it takes
//! one pooled request buffer, writes the reference with the §8.8 encoder, runs the proxy's step loop on a
//! borrowed `Caller`, and decodes the answer straight into `SecretAnswer` (VALUE, FACT(F_LEASE_S)?). The only
//! box is the port's.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::fail::{fact, refused, CallError, FaultReason};
use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use busbar_plugin_abi::host_side::driver::Driver;
use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::host_side::pool::Pool;
use busbar_plugin_abi::host_side::scrub::{fail_text, Scrub};
use busbar_plugin_abi::kinds::secret::secret::{tag, F_LEASE_S};
use busbar_plugin_abi::records::{FactRec, RecErr, Records};
use busbar_plugin_abi::types::Status;

use crate::call::kinds::secret::Proxy;
use busbar_ports::codec::secret::encode_reference;
use busbar_ports::secret::{SecretAnswer, SecretPort};
use busbar_ports::PluginCode;
use busbar_ports::{CallCx, PortError};

use crate::instance::ErrorBook;

/// The secret port over one instance's proxy.
pub struct SecretAdapter<N: Needs> {
    proxy: Proxy,
    needs: Arc<N>,
    /// The image's `ErrorBook` (§11.2), for the ERROR number of a REFUSED or FAILED answer.
    errors: &'static ErrorBook,
    /// The undeclared-number WARN latch (once per instance).
    latch: AtomicBool,
}

impl<N: Needs> SecretAdapter<N> {
    /// Built by `Registry::open_secret` after INSTANCE: `errors` is the owning image's book.
    pub fn new(proxy: Proxy, needs: Arc<N>, errors: &'static ErrorBook) -> Self {
        Self {
            proxy,
            needs,
            errors,
            latch: AtomicBool::new(false),
        }
    }
}

impl<N: Needs> SecretPort for SecretAdapter<N> {
    fn resolve<'a>(
        &'a self,
        cx: CallCx,
        reference: &'a [u8],
    ) -> BoxFut<'a, Result<SecretAnswer, PortError>> {
        Box::pin(async move {
            let inst = self.proxy.instance();
            let mut req = Pool::global().acquire(inst.max_out);
            if encode_reference(&mut req, reference).is_err() {
                return Err(port_failure(
                    &inst.scrub,
                    false,
                    refused::R_INVALID,
                    "the secret reference does not fit the request buffer",
                    None,
                    None,
                    None,
                ));
            }
            // Borrowed from the instance the proxy already borrows: no refcount traffic. `Driver::new` writes the
            // chain id; the stack is the one outside this call (custody pushed the caller already, §12.2).
            let caller = Caller {
                plugin: &inst.identity,
                kind: inst.kind,
                name: &inst.name,
                instance: inst.id,
                slot: inst.slot,
                chain: 0,
                deadline: cx.deadline,
                stack: cx.stack,
                out_of_process: false,
                limits: inst.limits,
            };
            let mut drv = Driver::new(&*self.needs, caller);
            let owned = self
                .proxy
                .resolve(&mut drv, crate::call::at(&cx), req)
                .await
                .map_err(PortError::Call)?;
            let answer = owned.answer();
            let error = self.errors.resolve(answer.fail_error(), &self.latch);
            match decode_answer(&inst.scrub, &answer, error) {
                Ok(answer) => Ok(answer),
                Err(e @ PortError::Call(_)) => {
                    inst.quarantine();
                    Err(e)
                }
                Err(e) => Err(e),
            }
        })
    }
}

/// The answer to a `PortError` or a `SecretAnswer`: REFUSED and FAILED become the port's refusal and failure
/// (text through `fail_text`, FAILED facts), an OK answer is `answer_value`, and a malformed OK answer is
/// `Call(Fault(BadRecords))` (the caller quarantines).
fn decode_answer(
    scrub: &Scrub,
    a: &Answer<'_>,
    error: Option<PluginCode>,
) -> Result<SecretAnswer, PortError> {
    if a.is_ok() {
        return answer_value(a.records())
            .map_err(|e| PortError::Call(CallError::Fault(FaultReason::BadRecords(e))));
    }
    let (code, text) = a
        .fail()
        .ok_or(PortError::Call(CallError::Fault(FaultReason::MissingFail)))?;
    let failed = a.status == Status::FAILED;
    Err(port_failure(
        scrub,
        failed,
        code,
        text,
        a.fail_fact(fact::FACT_RETRY_AFTER_S),
        a.fail_fact(fact::FACT_BACKEND_STATUS),
        error,
    ))
}

/// The OK answer of `resolve`: exactly one VALUE and at most one FACT(F_LEASE_S) (IF §8.2). Anything else is a
/// contract break (`Unknown` for a foreign tag, `Size` for a missing or repeated record or another fact).
pub fn answer_value(recs: Records<'_>) -> Result<SecretAnswer, RecErr> {
    let mut value = None;
    let mut lease_s = None;
    for rec in recs {
        let rec = rec?;
        match rec.tag {
            tag::VALUE if value.is_none() => {
                let mut v = SecureVec::new();
                v.extend_from_slice(rec.body);
                value = Some(v);
            }
            busbar_plugin_abi::records::tag::FACT if lease_s.is_none() => {
                let f = rec.pod::<FactRec>()?;
                if f._r != 0 {
                    return Err(RecErr::Reserved);
                }
                if f.key != F_LEASE_S {
                    return Err(RecErr::Size);
                }
                lease_s = Some(f.value);
            }
            tag::VALUE | busbar_plugin_abi::records::tag::FACT => return Err(RecErr::Size),
            other => return Err(RecErr::Unknown(other)),
        }
    }
    Ok(SecretAnswer {
        value: value.ok_or(RecErr::Size)?,
        lease_s,
    })
}

/// The one failure shape of a REFUSED or FAILED answer: the plugin's text scrubbed whole, then cut to the shown
/// bound (`fail_text`, §12.16), and, for FAILED only, the backend's two facts as it stated them. A refusal
/// carries no facts.
pub fn port_failure(
    scrub: &Scrub,
    failed: bool,
    code: u32,
    text: &str,
    retry_after_s: Option<u64>,
    backend_status: Option<u64>,
    error: Option<PluginCode>,
) -> PortError {
    let text: Box<str> = fail_text(scrub, text).into_owned().into_boxed_str();
    if failed {
        PortError::Failed {
            code,
            text,
            retry_after_s,
            backend_status,
            error,
        }
    } else {
        PortError::Refused { code, text, error }
    }
}

#[cfg(test)]
#[path = "secret_tests.rs"]
mod tests;
