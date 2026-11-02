// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A SECRET PLUGIN'S ANSWER goes directly into host-owned secret memory: the resolved value goes

use zeroize::Zeroize;

use super::Held;
use crate::abi::mechanism::call::Outcome;
use crate::abi::sdk::life::Refusal;
use crate::abi::sdk::{Lent, Out};
use crate::abi::secret::{
    ResolveIn, ResolveOut, ERROR_KIND_INVALID, ERROR_KIND_UNSET, MAX_SECRET_BYTES,
};

/// The refusal of a value that resolved to nothing: a secret is never resolved empty.
pub const EMPTY_VALUE: &str =
    "the secret resolved to an EMPTY value; a secret must be non-empty (fail-closed)";

/// Answer `resolve` with `value`: written into the host's buffer (READY), or, when it does not fit,

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
    if bytes.len() > MAX_SECRET_BYTES {
        out.set(|o| &o.error_kind, ERROR_KIND_INVALID);
        return out.fail(Refusal::failed(format!(
            "the secret is {} bytes, over the {MAX_SECRET_BYTES}-byte limit a secret may be",
            bytes.len()
        )));
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
