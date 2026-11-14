// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The operating-system-seeded AWS-LC random number generator.

use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};

use crate::Error;

/// Fill `buf` with random bytes.
#[inline]
pub fn fill(buf: &mut [u8]) -> Result<(), Error> {
    SystemRandom::new().fill(buf).map_err(|_| Error::Rng)
}

/// A random `u64`.
#[inline]
pub fn u64() -> Result<u64, Error> {
    let mut b = [0_u8; 8];
    fill(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

/// HKDF-SHA256 (RFC 5869) of `ikm` under `salt` and `info`, into `out` (at most 255 * 32 bytes).
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), Error> {
    use aws_lc_rs::hkdf;
    struct Len(usize);
    impl hkdf::KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(ikm);
    let info = [info];
    let okm = prk
        .expand(&info, Len(out.len()))
        .map_err(|_| Error::Invalid("HKDF output length"))?;
    okm.fill(out)
        .map_err(|_| Error::Invalid("HKDF output length"))
}

/// PBKDF2-HMAC-SHA256 (RFC 8018) of `password` under `salt` with `iterations` (at least 1), into
/// `out`. The software backend refuses no parameter beyond a zero iteration count.
pub fn pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
) -> Result<(), Error> {
    use aws_lc_rs::pbkdf2;
    let iterations = core::num::NonZeroU32::new(iterations)
        .ok_or(Error::Invalid("PBKDF2 needs at least one iteration"))?;
    if out.is_empty() {
        return Err(Error::Invalid("PBKDF2 output is empty"));
    }
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, iterations, salt, password, out);
    Ok(())
}
