// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`CoreJwsSigner`]: SIGN over the host's signing key, the `busbar_crypto::Signer` seam (IF §12.11,
//! CRYPTO-SEAM §2.6). Core picks the alg and the kid; key bytes never leave the signer.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use busbar_contract::crypto::{SigAlg, Signer};
use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};

use super::{HostSigner, SignedJws};
use crate::plugin_records::RecordsDenied;

/// Signs JWS (RFC 7515) with the host's key. The private-key operation is blocking (a KMS or HSM signer may
/// call out), so it runs on the blocking pool, never on the request task.
pub struct CoreJwsSigner {
    signer: Arc<dyn Signer>,
    protected: Box<str>,
}

impl CoreJwsSigner {
    pub fn new(signer: Arc<dyn Signer>) -> Self {
        let key = signer.public_key();
        let alg = match key.alg {
            SigAlg::Ed25519 => "EdDSA",
            SigAlg::EcdsaP256Sha256 => "ES256",
        };
        let header = format!(r#"{{"alg":"{alg}","kid":"{}"}}"#, key.key_id);
        Self {
            signer,
            protected: URL_SAFE_NO_PAD.encode(header).into(),
        }
    }
}

impl HostSigner for CoreJwsSigner {
    fn sign_jws<'a>(
        &'a self,
        who: &'a Caller<'_>,
        payload: &'a [u8],
        detached: bool,
    ) -> BoxFut<'a, Result<SignedJws, RecordsDenied>> {
        let _ = who;
        Box::pin(async move {
            let payload64 = URL_SAFE_NO_PAD.encode(payload);
            let input = format!("{}.{payload64}", self.protected).into_bytes();
            let signer = Arc::clone(&self.signer);
            let signature = tokio::task::spawn_blocking(move || {
                let mut out = Vec::new();
                signer.sign(&input, &mut out).map(|()| out)
            })
            .await
            .map_err(|_| RecordsDenied::Unavailable)?
            .map_err(|_| RecordsDenied::Unavailable)?;
            let signature: Box<str> = URL_SAFE_NO_PAD.encode(signature).into();
            Ok(if detached {
                SignedJws::Detached {
                    protected: self.protected.clone(),
                    signature,
                }
            } else {
                SignedJws::Compact(format!("{}.{payload64}.{signature}", self.protected).into())
            })
        })
    }
}
