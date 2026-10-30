// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A SECRET PLUGIN'S ANSWER (the credential chip, row 6: host-owned secret bytes): the resolved value goes
//! straight into the HOST'S zeroed buffer (`ResolveIn::secret_buf`) and the plugin's own copy is
//! wiped as the answer is made. No lease, no copy left on the plugin's side, and no getter on the
//! way: the value reaches the SDK in a [`Held`] and leaves it only into host memory.

use zeroize::Zeroize;

use super::Held;
use crate::abi::mechanism::call::Outcome;
use crate::abi::sdk::life::Refusal;
use crate::abi::sdk::{Lent, Out};
use crate::abi::secret::{ResolveIn, ResolveOut, ERROR_KIND_INVALID, ERROR_KIND_UNSET};

/// The refusal of a value that resolved to nothing: a secret is never resolved empty.
pub const EMPTY_VALUE: &str =
    "the secret resolved to an EMPTY value; a secret must be non-empty (fail-closed)";

/// Answer `resolve` with `value`: written into the host's buffer (READY), or, when it does not fit,
/// the short-buffer answer naming its full length (FAILED, `needed`; the host re-calls once with a
/// buffer that size and the plugin resolves again). An empty value is FAILED, `ERROR_KIND_INVALID`
/// ([`EMPTY_VALUE`]): the host refuses a READY answer that names no material. `value` is wiped
/// before this returns, either way.
pub fn resolved<V: Zeroize + AsRef<[u8]>>(
    input: Lent<'_, ResolveIn>,
    out: &mut Out<'_, ResolveOut>,
    value: Held<V>,
) -> Outcome {
    let bytes = value.wire().as_ref();
    let mut buf = input.secret_buf();
    if bytes.is_empty() {
        out.set(|o| &o.error_kind, ERROR_KIND_INVALID);
        return out.fail(Refusal::failed(EMPTY_VALUE.to_string()));
    }
    out.set(|o| &o.error_kind, ERROR_KIND_UNSET);
    if bytes.len() > buf.cap() {
        out.set(|o| &o.needed, bytes.len() as u64);
        return Outcome::Failed;
    }
    buf.extend(bytes);
    out.host_secret(|o| &o.secret, &buf, bytes.len());
    Outcome::Ready
}
