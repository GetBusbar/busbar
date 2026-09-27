// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AWS Signature Version 4, at its historical `busbar_kernel::sigv4` path: the INBOUND check the
//! ingress auth chain runs (the identity unit's, #83a O1) and the signing helpers it shares with the
//! egress signer.

pub use busbar_contract::redacted::sha256_hex;
pub use busbar_kernel_identity::egress_auth::sigv4::{
    format_amz_time, uri_encode_path, SIGV4_ALGORITHM,
};
pub use busbar_kernel_identity::ingress_sigv4::*;
