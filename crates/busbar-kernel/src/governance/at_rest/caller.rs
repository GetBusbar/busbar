// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Binary authenticated custody for caller grants and their protected intents.
//! Rotation admission is the root's writer-barrier/complete-rewrap obligation.
use busbar_contract::crypto::{self, Aes256Gcm};
use busbar_contract::secure::{SecureArray, SecureVec};
use std::sync::Arc;

const MAGIC: &[u8; 4] = b"BCG1";
const OVERHEAD: usize = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallerRecordError {
    Invalid,
    Budget,
    Crypto,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CallerRecordKind {
    Grant = 1,
    Guard = 2,
    Prepared = 3,
    Terminal = 4,
}
impl CallerRecordKind {
    fn schema(self) -> &'static [u8] {
        match self {
            Self::Grant => b"grant-v1",
            Self::Guard => b"grant-guard-v1",
            Self::Prepared | Self::Terminal => b"grant-intent-v1",
        }
    }
}

/// Borrowed expected host context; decoding an envelope never constructs authority.
pub struct CallerRecordContext<'a> {
    kind: CallerRecordKind,
    dataset: [u8; 16],
    domain: [u8; 16],
    key: &'a [u8],
    generation: u64,
    operation: [u8; 16],
    binding: &'a [u8],
}
impl<'a> CallerRecordContext<'a> {
    pub fn new(
        kind: CallerRecordKind,
        dataset: [u8; 16],
        domain: [u8; 16],
        key: &'a [u8],
        generation: u64,
        operation: [u8; 16],
        binding: &'a [u8],
    ) -> Result<Self, CallerRecordError> {
        if dataset == [0; 16]
            || domain == [0; 16]
            || key.is_empty()
            || generation == 0
            || (kind != CallerRecordKind::Grant && operation == [0; 16])
            || u32::try_from(key.len()).is_err()
            || u32::try_from(binding.len()).is_err()
        {
            return Err(CallerRecordError::Invalid);
        }
        Ok(Self {
            kind,
            dataset,
            domain,
            key,
            generation,
            operation,
            binding,
        })
    }
    fn aad_len(&self) -> Option<usize> {
        // Fixed framed domain/instance/schema, version/kind, IDs and lengths.
        2usize
            .checked_add(16 + 16 + 8 + 16 + 8)?
            .checked_add(self.key.len())?
            .checked_add(self.binding.len())?
            .checked_add(16 + b"caller-connections".len() + self.kind.schema().len())
    }
    fn aad(&self, kid: &[u8; 8]) -> Result<SecureVec, CallerRecordError> {
        let cap = self.aad_len().ok_or(CallerRecordError::Budget)?;
        let mut aad = SecureVec::with_capacity(cap).map_err(|_| CallerRecordError::Budget)?;
        for part in [
            &[1, self.kind as u8][..],
            &self.dataset,
            &self.domain,
            &self.generation.to_be_bytes(),
            &self.operation,
            kid,
        ] {
            aad.extend(part).map_err(|_| CallerRecordError::Budget)?;
        }
        for part in [
            b"caller-connections".as_slice(),
            self.kind.schema(),
            self.key,
            self.binding,
        ] {
            let len = u32::try_from(part.len()).map_err(|_| CallerRecordError::Budget)?;
            aad.extend(&len.to_be_bytes())
                .map_err(|_| CallerRecordError::Budget)?;
            aad.extend(part).map_err(|_| CallerRecordError::Budget)?;
        }
        Ok(aad)
    }
}

struct Keys {
    kid: [u8; 8],
    grant: Aes256Gcm,
    intent: Aes256Gcm,
}
impl Keys {
    fn derive(material: &[u8]) -> Self {
        let derive = |label: &[u8]| {
            let mut raw = SecureArray::<32>::zeroed();
            crypto::hkdf_sha256(&[], material, label, &mut raw[..]).expect("32-byte HKDF output");
            raw
        };
        let kid = crypto::sha256(&derive(b"busbar caller-record kid v1")[..]);
        let mut short = [0; 8];
        short.copy_from_slice(&kid[..8]);
        Self {
            kid: short,
            grant: Aes256Gcm::new(&derive(b"busbar caller-grant at-rest v1"))
                .expect("32-byte AES key"),
            intent: Aes256Gcm::new(&derive(b"busbar caller-intent at-rest v1"))
                .expect("32-byte AES key"),
        }
    }
    fn cipher(&self, kind: CallerRecordKind) -> &Aes256Gcm {
        if kind == CallerRecordKind::Grant {
            &self.grant
        } else {
            &self.intent
        }
    }
}
pub(super) struct CallerKeys {
    current: Keys,
    previous: Option<Keys>,
}
impl CallerKeys {
    pub(super) fn new(current: &[u8], previous: Option<&[u8]>) -> Self {
        Self {
            current: Keys::derive(current),
            previous: previous.map(Keys::derive),
        }
    }
}

/// Actual at-rest producer; no injectable crypto implementation or plaintext mode.
#[derive(Clone)]
pub struct CallerProtectedRecords {
    keys: Arc<CallerKeys>,
    max_bytes: usize,
}
impl std::fmt::Debug for CallerProtectedRecords {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CallerProtectedRecords(<protected>)")
    }
}
impl CallerProtectedRecords {
    pub(super) fn new(keys: Arc<CallerKeys>, max_bytes: usize) -> Result<Self, CallerRecordError> {
        if max_bytes == 0 {
            return Err(CallerRecordError::Budget);
        }
        Ok(Self { keys, max_bytes })
    }
    fn check(
        &self,
        context: &CallerRecordContext<'_>,
        plain_len: usize,
    ) -> Result<(), CallerRecordError> {
        let total = context
            .aad_len()
            .and_then(|n| n.checked_add(OVERHEAD))
            .and_then(|n| n.checked_add(plain_len.checked_mul(2)?))
            .ok_or(CallerRecordError::Budget)?;
        if total > self.max_bytes {
            Err(CallerRecordError::Budget)
        } else {
            Ok(())
        }
    }
    pub fn seal(
        &self,
        context: &CallerRecordContext<'_>,
        plain: &[u8],
    ) -> Result<SecureVec, CallerRecordError> {
        self.check(context, plain.len())?;
        let keys = &self.keys.current;
        let aad = context.aad(&keys.kid)?;
        let mut body =
            SecureVec::with_capacity(plain.len()).map_err(|_| CallerRecordError::Budget)?;
        body.extend(plain).map_err(|_| CallerRecordError::Budget)?;
        let (nonce, tag) = keys
            .cipher(context.kind)
            .seal_random_nonce(&aad, &mut body[..])
            .map_err(|_| CallerRecordError::Crypto)?;
        let mut output = SecureVec::with_capacity(OVERHEAD + plain.len())
            .map_err(|_| CallerRecordError::Budget)?;
        for part in [MAGIC.as_slice(), &keys.kid, &nonce, &tag, &body] {
            output.extend(part).map_err(|_| CallerRecordError::Budget)?;
        }
        Ok(output)
    }
    pub fn open(
        &self,
        context: &CallerRecordContext<'_>,
        envelope: &[u8],
    ) -> Result<SecureVec, CallerRecordError> {
        let size = envelope
            .len()
            .checked_sub(OVERHEAD)
            .ok_or(CallerRecordError::Invalid)?;
        self.check(context, size)?;
        if envelope.get(..4) != Some(MAGIC.as_slice()) {
            return Err(CallerRecordError::Invalid);
        }
        let keys = if envelope[4..12] == self.keys.current.kid {
            &self.keys.current
        } else {
            self.keys
                .previous
                .as_ref()
                .filter(|k| envelope[4..12] == k.kid)
                .ok_or(CallerRecordError::Crypto)?
        };
        let nonce = envelope[12..24]
            .try_into()
            .map_err(|_| CallerRecordError::Invalid)?;
        let tag = envelope[24..40]
            .try_into()
            .map_err(|_| CallerRecordError::Invalid)?;
        let aad = context.aad(&keys.kid)?;
        let mut body = SecureVec::with_capacity(size).map_err(|_| CallerRecordError::Budget)?;
        body.extend(&envelope[40..])
            .map_err(|_| CallerRecordError::Budget)?;
        keys.cipher(context.kind)
            .open_in_place(&nonce, &aad, &mut body[..], &tag)
            .map_err(|_| CallerRecordError::Crypto)?;
        Ok(body)
    }
}
