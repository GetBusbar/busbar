// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Covered output projection and payload storage share the ingress process account (#420).
//! Generic recorder maintenance and self-owning Bytes/HTTP/Arc control metadata are excluded.
//! Reservations here never record metrics: projection may hold recorder registry read guards.

use super::process_admission::{ByteCredit, RequestLease};
use busbar_contract::secure::SecureVec;
use std::io;

/// Capacity refusal is distinct from allocator failure and serializer failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputError {
    Capacity,
    Allocation,
    Encoding,
}

impl OutputError {
    /// Call exactly once at the outer response boundary, after all projection guards retire.
    /// The legacy gate name identifies the now shared inbound/covered-output byte account.
    pub fn report(self) {
        if self == Self::Capacity {
            metrics::counter!(crate::snapshot::ADMISSION_DENIED_TOTAL, "gate" => "inbound_body_bytes")
                .increment(1);
        }
    }

    fn io(self) -> io::Error {
        io::Error::from(match self {
            Self::Capacity => io::ErrorKind::OutOfMemory,
            Self::Allocation => io::ErrorKind::OutOfMemory,
            Self::Encoding => io::ErrorKind::InvalidData,
        })
    }
}

/// Conservative monotonic requested-allocation credit for one projection/encoding operation.
/// Temporary allocations remain charged until the complete captured object retires.
pub struct CaptureScope {
    credit: ByteCredit,
}

impl CaptureScope {
    pub fn new(request: &RequestLease) -> Result<Self, OutputError> {
        Ok(Self {
            credit: request
                .try_reserve_unreported(0)
                .map_err(|_| OutputError::Capacity)?,
        })
    }

    pub fn reserve_requested(&mut self, bytes: usize) -> Result<(), OutputError> {
        let next = self
            .credit
            .request()
            .try_reserve_unreported(bytes)
            .map_err(|_| OutputError::Capacity)?;
        // Both credits originate from the same request; a rejected merge still returns its
        // owner, which is dropped here rather than losing or detaching its count/byte custody.
        self.credit
            .try_merge(next)
            .map_err(|_| OutputError::Capacity)
    }

    pub(crate) fn copy_str(&mut self, text: &str) -> Result<String, OutputError> {
        self.reserve_requested(text.len())?;
        Ok(text.to_owned())
    }

    pub(crate) fn vector<T>(&mut self, capacity: usize) -> Result<Vec<T>, OutputError> {
        self.reserve_requested(
            capacity
                .checked_mul(std::mem::size_of::<T>())
                .ok_or(OutputError::Capacity)?,
        )?;
        Ok(Vec::with_capacity(capacity))
    }

    /// Charge the complete replacement allocation while the old vector is still retained.
    pub(crate) fn grow_vector<T>(
        &mut self,
        vector: &mut Vec<T>,
        additional: usize,
    ) -> Result<(), OutputError> {
        let needed = vector
            .len()
            .checked_add(additional)
            .ok_or(OutputError::Capacity)?;
        if needed > vector.capacity() {
            let capacity = needed.max(
                vector
                    .capacity()
                    .checked_mul(2)
                    .ok_or(OutputError::Capacity)?,
            );
            self.reserve_requested(
                capacity
                    .checked_mul(std::mem::size_of::<T>())
                    .ok_or(OutputError::Capacity)?,
            )?;
            vector.reserve_exact(capacity - vector.len());
        }
        Ok(())
    }

    pub(crate) fn finish<T>(self, value: T) -> Captured<T> {
        Captured { value, scope: self }
    }
}

/// Returned projection storage drops before the credit which accounts for its backing.
/// There is deliberately no owned-value extraction or mutable access to the projection.
pub struct Captured<T> {
    value: T,
    scope: CaptureScope,
}

impl<T> Captured<T> {
    #[must_use]
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Preflight the closed serializer's scratch before invoking it.
    pub fn reserve_encoding(&mut self, bytes: usize) -> Result<(), OutputError> {
        self.scope.reserve_requested(bytes)
    }

    #[must_use]
    pub fn request(&self) -> &RequestLease {
        self.scope.credit.request()
    }
}

/// Secure payload storage whose charge follows the actual shared Bytes backing owner.
pub struct OutputBuffer {
    // Rust drops fields in declaration order: wipe/free payload BEFORE releasing byte credit.
    bytes: SecureVec,
    credit: ByteCredit,
    failure: Option<OutputError>,
}

impl OutputBuffer {
    pub fn with_capacity(request: &RequestLease, capacity: usize) -> Result<Self, OutputError> {
        let credit = request
            .try_reserve_unreported(capacity)
            .map_err(|_| OutputError::Capacity)?;
        let bytes = SecureVec::with_capacity(capacity).map_err(|_| OutputError::Allocation)?;
        Ok(Self {
            bytes,
            credit,
            failure: None,
        })
    }

    #[must_use]
    pub fn failure(&self) -> Option<OutputError> {
        self.failure
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), OutputError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        let needed = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(OutputError::Capacity)?;
        if needed > self.bytes.capacity() {
            let capacity = needed.max(if self.bytes.capacity() == 0 {
                1024
            } else {
                self.bytes
                    .capacity()
                    .checked_mul(2)
                    .ok_or(OutputError::Capacity)?
            });
            let credit = self
                .credit
                .request()
                .try_reserve_unreported(capacity)
                .map_err(|_| OutputError::Capacity)?;
            let mut next =
                SecureVec::with_capacity(capacity).map_err(|_| OutputError::Allocation)?;
            // Existing bytes fit in the explicitly allocated extent; no implicit growth.
            next.extend(self.bytes.as_slice())
                .map_err(|_| OutputError::Allocation)?;
            let previous_bytes = std::mem::replace(&mut self.bytes, next);
            let previous_credit = std::mem::replace(&mut self.credit, credit);
            drop(previous_bytes);
            drop(previous_credit);
        }
        self.bytes
            .extend(bytes)
            .map_err(|_| OutputError::Allocation)
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), OutputError> {
        let result = self.append(bytes);
        if let Err(error) = result {
            self.failure = Some(error);
        }
        result
    }

    /// Consumers must complete serialization successfully before publishing these bytes.
    #[must_use]
    pub fn into_bytes(self) -> bytes::Bytes {
        bytes::Bytes::from_owner(self)
    }
}

impl AsRef<[u8]> for OutputBuffer {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl io::Write for OutputBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.write_bytes(bytes).map_err(OutputError::io)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
