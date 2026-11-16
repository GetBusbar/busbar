// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Errors: the plugin-side `Fail`, its codes and fact keys, and the host-side `CallError` (IF §4.1, §4.2).

use std::borrow::Cow;

use crate::host::CryptoErr;
use crate::need::need::NeedErr;
use crate::records::{Full, RecErr};
use crate::types::Status;

/// The only error a kind method or `Open` returns. REFUSED = a domain verdict, FAILED = the backend failed.
/// The text is shown to operators and audited, never to another kind or a client (I2): core scrubs it (I14,
/// §12.16) and renders client-facing refusals from generic codes with its own text (§12.15). The plugin
/// writes plain text and does no masking. **Round 15 (I14):** the shim cuts it only to `FAIL_TEXT_WIRE_MAX`
/// (3,072 bytes, at a char boundary), which always fits the first 4 KiB buffer; it never cuts to the 512 bytes
/// core shows, because a cut before the scrub can split a secret so that no whole needle matches. Core scrubs
/// the whole received text, masks a trailing partial needle, and only then cuts to 512 (§12.16
/// `scrub::fail_text`, C-SCRUB-CUT). A plugin passes upstream error text whole; it never slices it itself.
/// **Round 21 (185):** a FAILED Fail may carry the backend's own facts, never a decision: `FACT_RETRY_AFTER_S`
/// (the backend's Retry-After, as it said it) and `FACT_BACKEND_STATUS` (its status number). The shim writes
/// them as FACT records after the FAIL record (§6.4 step 2); core reads them into `PortError::Failed` and decides
/// what they mean (§11.3, §12.3, §8.3 login outage). Unlike everything else a failing method wrote, they are not
/// zeroed: they are two numbers the plugin chose to state, never a credential.
/// **Round 34 (PLUGIN-ERROR-CODES):** a Fail may carry one of the plugin's declared error numbers (D_ERRORS,
/// `Describe::errors`). The shim writes it as one ERROR record directly after FAIL, before any FACT, when it is
/// not 0. It is display only, so REFUSED may carry it and `code` keeps its meaning. Core renders it as
/// `BUSBAR-<identity>-NNNN` in its own `plugin_diag` field beside the text (§11.2, §12.16); an undeclared number
/// renders no code and is never FAULT.
#[derive(Debug, Clone)]
pub struct Fail {
    status: Status,
    code: u32,
    text: Cow<'static, str>,
    facts: [Option<u64>; 2],
    error: u16,
}
impl Fail {
    /// The one constructor every other one goes through (IF §1, the fail.rs row).
    const fn of(status: Status, code: u32, text: Cow<'static, str>) -> Self {
        Fail {
            status,
            code,
            text,
            facts: [None; 2],
            error: 0,
        }
    }
    pub const fn refused(code: u32) -> Self {
        Self::of(Status::REFUSED, code, Cow::Borrowed(""))
    }
    pub fn refused_because(code: u32, text: impl Into<Cow<'static, str>>) -> Self {
        Self::of(Status::REFUSED, code, text.into())
    }
    pub const fn failed(code: u32) -> Self {
        Self::of(Status::FAILED, code, Cow::Borrowed(""))
    }
    pub fn failed_because(code: u32, text: impl Into<Cow<'static, str>>) -> Self {
        Self::of(Status::FAILED, code, text.into())
    }
    /// REFUSED R_UNSUPPORTED: a method this plugin does not implement (the kind trait's default body).
    pub const fn unsupported() -> Self {
        Self::refused(refused::R_UNSUPPORTED)
    }
    /// Round 21. Sets one fact (`key` in `FAIL_FACT_KEYS`; setting it again replaces the value). A key outside
    /// `FAIL_FACT_KEYS`, or a REFUSED Fail, ignores the call: REFUSED is a verdict and carries no facts.
    /// `Fail::failed_because(F_UNAVAILABLE, text).with_fact(fact::FACT_RETRY_AFTER_S, 30)`.
    pub fn with_fact(mut self, key: u32, value: u64) -> Self {
        if self.status == Status::FAILED
            && let Some(slot) = FAIL_FACT_KEYS.iter().position(|&known| known == key)
        {
            self.facts[slot] = Some(value);
        }
        self
    }
    /// The set facts, in `FAIL_FACT_KEYS` order (what the shim writes).
    pub fn facts(&self) -> impl Iterator<Item = (u32, u64)> + '_ {
        FAIL_FACT_KEYS
            .into_iter()
            .zip(self.facts)
            .filter_map(|(key, value)| value.map(|value| (key, value)))
    }
    /// Round 34. The plugin's declared error number (0 clears), on REFUSED or FAILED. Display only.
    /// `Fail::failed_because(F_UPSTREAM, text).with_error(7071)`.
    pub fn with_error(mut self, number: u16) -> Self {
        self.error = number;
        self
    }
    /// Round 34. The number `with_error` set, 0 = none (what the shim writes as ERROR).
    pub fn error(&self) -> u16 {
        self.error
    }
    pub fn status(&self) -> Status {
        self.status
    }
    pub fn code(&self) -> u32 {
        self.code
    }
    pub fn text(&self) -> &str {
        &self.text
    }
}
/// Round 21: the only facts a FAILED answer carries after its FAIL record, in this order.
pub const FAIL_FACT_KEYS: [u32; 2] = [fact::FACT_RETRY_AFTER_S, fact::FACT_BACKEND_STATUS];
impl From<Full> for Fail {
    fn from(_: Full) -> Self {
        Fail::failed(failed::F_LIMIT)
    }
}
impl From<RecErr> for Fail {
    fn from(_: RecErr) -> Self {
        Fail::refused(refused::R_INVALID)
    }
}
/// The §6.3 mapping. The texts are fixed strings.
impl From<NeedErr> for Fail {
    fn from(e: NeedErr) -> Self {
        let (status, code, text) = match e {
            NeedErr::Denied => (Status::REFUSED, refused::R_DENIED, "core refused the step"),
            NeedErr::Absent => (
                Status::REFUSED,
                refused::R_NOT_FOUND,
                "the step found nothing",
            ),
            NeedErr::Taken => (
                Status::REFUSED,
                refused::R_CONFLICT,
                "the step lost to another holder",
            ),
            NeedErr::Unavailable => (
                Status::FAILED,
                failed::F_UNAVAILABLE,
                "the destination is unavailable",
            ),
            NeedErr::Closed => (
                Status::FAILED,
                failed::F_UNAVAILABLE,
                "the connection is closed",
            ),
            NeedErr::Tls => (
                Status::FAILED,
                failed::F_UNAVAILABLE,
                "the TLS handshake failed",
            ),
            NeedErr::Timeout => (Status::FAILED, failed::F_TIMEOUT, "the step timed out"),
            NeedErr::Limit => (Status::FAILED, failed::F_LIMIT, "the step passed a limit"),
            NeedErr::Skipped => (Status::FAILED, failed::F_INTERNAL, "the step was skipped"),
            NeedErr::Invalid => (Status::FAILED, failed::F_INTERNAL, "the step was malformed"),
        };
        Self::of(status, code, Cow::Borrowed(text))
    }
}
/// Round 23: Rng (status RNG: the DRBG failed or the backend's self-test failed, §5.2) is a backend failure,
/// so FAILED F_UNAVAILABLE, which core may retry or reroute (§12.3) and renders 502 (§12.15); only Unavailable
/// (the backend refuses the alg) is the REFUSED R_UNSUPPORTED verdict.
impl From<CryptoErr> for Fail {
    fn from(e: CryptoErr) -> Self {
        // FU3 (B30): `check` judges a configuration, never a credential, so a crypto Err there is the module
        // failing, not a verdict on a setting: FAILED, whatever the status (`Limit` keeps its own code).
        if IN_CHECK.get() {
            return match e {
                CryptoErr::Limit => Fail::failed(failed::F_LIMIT),
                CryptoErr::Bad | CryptoErr::Unavailable | CryptoErr::Invalid | CryptoErr::Rng => {
                    Fail::failed(failed::F_UNAVAILABLE)
                }
            };
        }
        match e {
            CryptoErr::Bad => Fail::refused(refused::R_DENIED),
            CryptoErr::Unavailable => Fail::refused(refused::R_UNSUPPORTED),
            CryptoErr::Invalid => Fail::refused(refused::R_INVALID),
            CryptoErr::Limit => Fail::failed(failed::F_LIMIT),
            CryptoErr::Rng => Fail::failed(failed::F_UNAVAILABLE),
        }
    }
}

std::thread_local! {
    /// True while the shim runs the plugin's `check` on this thread (FU3). A `const` `Cell<bool>` has no destructor
    /// (I13: abi's plugin-side thread-locals have none).
    static IN_CHECK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Runs `f` (the plugin's `check`) with `From<CryptoErr> for Fail` in its FU3 mode, restoring the flag even if `f`
/// unwinds (the shim's `catch_unwind` sits outside).
pub(crate) fn in_check<R>(f: impl FnOnce() -> R) -> R {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            IN_CHECK.set(self.0);
        }
    }
    let _restore = Restore(IN_CHECK.replace(true));
    f()
}

/// Round 15: the most FAIL detail bytes the shim writes (C: `BB_FAIL_TEXT_WIRE_MAX`). Not the display length:
/// core shows at most `scrub::FAIL_TEXT_SHOWN` (512) bytes, cut after the scrub (§12.16).
pub const FAIL_TEXT_WIRE_MAX: usize = 3_072;

/// REFUSED codes 1..=0xFF are generic; 0x100.. are kind codes (declared in the kind's `consts {}`).
pub mod refused {
    pub const R_UNSUPPORTED: u32 = 1; // method or feature not offered by this plugin
    pub const R_INVALID: u32 = 2; // input malformed
    pub const R_NOT_FOUND: u32 = 3; // the named thing does not exist
    pub const R_DENIED: u32 = 4; // the backend refused this principal or request
    pub const R_CONFIG: u32 = 5; // the config is invalid (open, check)
    pub const R_CONFLICT: u32 = 6; // the backend reports a conflicting state
    // 7..=16: core-owned refusal vocabulary. Core writes these (with its own text) into the REFUSAL a plane
    // renders (§12.15); a plugin may also return them where they are true of its own domain.
    pub const R_AUTH_REQUIRED: u32 = 7; // no credential, or one no auth instance recognised
    pub const R_BAD_CREDENTIAL: u32 = 8; // a credential was presented and is invalid
    pub const R_EXPIRED: u32 = 9; // the credential or ticket has expired
    pub const R_RATE_LIMITED: u32 = 10; // core's rate or quota policy said no
    pub const R_BUDGET: u32 = 11; // core's spend budget said no
    pub const R_NO_ROUTE: u32 = 12; // no candidate upstream is available
    pub const R_POLICY: u32 = 13; // a policy decision (a hook verdict, an entitlement) refused it
    pub const R_CONNECT_REQUIRED: u32 = 14; // caller-mode binding (STYLE_CALLER) with no caller connection held (§12.12)
    pub const R_REPLAYED: u32 = 15; // a signed request was already seen (REPLAY claim lost, §8.3)
    pub const R_NOT_TRUSTED: u32 = 16; // the trust book refuses the counterparty or item (§12.14)
    /// `open`/`check` (round 31): the data or bag is a version this plugin does not convert (unknown, NEWER than
    /// it knows, or older than the supported source). Core fails that instance with the plugin's scrubbed text.
    pub const R_VERSION: u32 = 17;
}
/// FAILED codes. These are facts. Core alone decides whether to retry, reroute or give up (§12.3).
pub mod failed {
    pub const F_UNAVAILABLE: u32 = 1; // the backend is unreachable or down
    pub const F_TIMEOUT: u32 = 2; // the backend did not answer in time (Need TIMEOUT)
    pub const F_PROTOCOL: u32 = 3; // the backend spoke something this plugin cannot parse
    pub const F_INTERNAL: u32 = 4; // plugin bug or invariant broken, short of a panic
    pub const F_LIMIT: u32 = 5; // over max_out, a Need limit or a backend size limit
    pub const F_BUSY: u32 = 6; // the backend reports overload or lock contention
    pub const F_UPSTREAM: u32 = 7; // the backend answered with an error status (`with_fact(FACT_BACKEND_STATUS, n)` states it, r21)
}
/// Generic fact keys 1..=0xFF; kind keys are 0x100.. . Kind keys never leave their kind: core forwards only
/// generic keys from one kind's answer into another kind's input (I2), so kind ranges may overlap freely.
pub mod fact {
    /// The backend asked for a delay, in seconds as it said it (a fact, never a decision). Round 21: carried by a
    /// FAILED answer after FAIL (`Fail::with_fact`) into `PortError::Failed.retry_after_s`.
    pub const FACT_RETRY_AFTER_S: u32 = 1;
    /// The backend's own status number (HTTP, SQLSTATE class, ...). Round 21: likewise, into `backend_status`.
    pub const FACT_BACKEND_STATUS: u32 = 2;
    /// Core-written into an upstream P_HEAD (§8.6): 1 = the peer's key matched the operator's SPKI pin for that
    /// configured upstream (absent = no pin configured). Core refuses a mismatched peer before any byte is sent.
    pub const FACT_TLS_PIN: u32 = 3;
    /// Core-written into an upstream P_HEAD: 1 = core offered the configured client identity (mTLS) to the peer.
    pub const FACT_TLS_CLIENT_ID: u32 = 4;
    /// Request projection (plane `request` answer when RQ_PROJECT is set; copied by core, unchanged, into the
    /// hook view). Text keys are FACT_TEXT, the rest FACT. Replaces plane-llm `HookView` (exchange/project.rs).
    pub const PJ_MODEL: u32 = 0x10; // text: the model the client asked for
    pub const PJ_TOTAL_CHARS: u32 = 0x11; // screenable text chars, system included
    pub const PJ_MESSAGE_COUNT: u32 = 0x12; // wire turn count
    pub const PJ_TOOL_COUNT: u32 = 0x13; // declared tools (0 = none)
    pub const PJ_SYSTEM_CHARS: u32 = 0x14;
    pub const PJ_STREAM: u32 = 0x15; // 1 = client asked for a stream
    pub const PJ_MAX_TOKENS: u32 = 0x16; // client output cap, saturated
    pub const PJ_END_USER: u32 = 0x17; // text: end user as the dialect spells it
    pub const PJ_TEXT_COMPLETE: u32 = 0x18; // 1 = every prompt item was plain text (CONVERSATION is lossless)
}

/// What a proxy call returns instead of an answer. REFUSED and FAILED are answers, not CallErrors.
#[cfg(feature = "host")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// The plugin panicked or broke the contract. The instance is closed and reopened with backoff, audited `plugin_fault`.
    Fault(FaultReason),
    /// The chain passed its deadline. The driver cancelled it.
    Deadline,
    /// The caller dropped the future. `cancel` ran before the arguments were freed (r4 H5).
    Cancelled,
    /// The watchdog quarantined the instance (a sync call passed its ceiling). No new calls.
    Quarantined,
    /// The chain passed core's step cap (default 10,000).
    Steps,
    /// The method is not in the instance's declared D_METHODS.
    NotDeclared,
}
#[cfg(feature = "host")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultReason {
    Panic,
    BadStatus(u32),
    BadRecords(RecErr),
    UnknownTag(u16),
    MissingFail,
    MissingToken,
    NeedOutsideAsync,
    AwaitedForeign,
    NeedNotAllowed(u32),
    StaleHandle,
    BadInstance,
    /// A token from the wrong space (chain vs session, bit 63) or with a stale generation.
    BadToken,
    /// A once rule the host found a session answer to break (a second or late FORWARD, an item out of place, a
    /// USAGE it may not keep; §8.6): charged by the host, not found by the adapter's decode.
    OnceRule,
}
