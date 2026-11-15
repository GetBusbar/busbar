// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SDK'S COLD CODE (bad-patterns BP17): what the request-path modules beside it reach only
//! off the hot path (refusal and failure text). Every fn is `#[cold]` or `#[inline(never)]`, holds
//! no `while`/`loop`, and sweeps no request data.

/// Cold code of exchange, cred, chip, aead, digest, hmac, mask and secret_bytes.
pub(super) mod cred;
/// Cold code of hook, plane, services, completion_retirement and inspection_wire.
pub(super) mod hook;
/// Cold code of store, url, publish, export, out, lent, transport, auth_* and the other SDK modules.
pub(super) mod wire;
