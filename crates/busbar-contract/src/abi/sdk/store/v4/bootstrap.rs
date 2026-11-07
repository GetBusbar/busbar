// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Immutable protected native-lifecycle carriers. Raw pointers only lend the
//! owner's live allocations to the ABI; no unsealed slice accessor is provided.
use crate::abi::mechanism::call::{Blob, BLOB_OCTETS, BLOB_SECRET};
use crate::persistence::lifecycle::{self, Bounds, Error, OpenBinding, Request};
use crate::Secret;
use std::sync::Arc;

/// One canonical bootstrap body retained through pending and exact SHORT replay.
pub struct Bootstrap {
    request: Arc<Request>,
    encoded: Secret<Vec<u8>>,
    bounds: Bounds,
}
impl Bootstrap {
    /// Encode once into wiping custody under explicit aggregate bounds.
    pub fn new(request: Arc<Request>, bounds: Bounds) -> Result<Self, Error> {
        let encoded = lifecycle::codec::encode_request(&request, bounds)?;
        Ok(Self {
            request,
            encoded,
            bounds,
        })
    }
    /// The immutable semantic request; protected values remain sealed.
    pub fn request(&self) -> &Arc<Request> {
        &self.request
    }
    /// Admission dimensions retained for response decoding.
    pub fn bounds(&self) -> Bounds {
        self.bounds
    }
    /// Lend the exact canonical body for this owner's lifetime.
    pub fn blob(&self) -> Blob {
        Blob {
            ptr: self.encoded.0.as_ptr(),
            len: self.encoded.0.len(),
            fmt: BLOB_OCTETS,
            flags: BLOB_SECRET,
        }
    }
    /// Exact immutable retry comparison without exposing protected bytes.
    pub fn same_request(&self, other: &Self) -> bool {
        self.encoded == other.encoded && self.bounds == other.bounds
    }
}
impl std::fmt::Debug for Bootstrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bootstrap")
            .field("bounds", &self.bounds)
            .finish_non_exhaustive()
    }
}
/// Retained ordinary/recovery OPEN binding extension.
pub struct OpenBindingBytes {
    binding: OpenBinding,
    extensions: Secret<Vec<u8>>,
}
impl OpenBindingBytes {
    /// Encode the strict binding and its extension envelope into one retained owner.
    pub fn new(binding: OpenBinding, bounds: Bounds) -> Result<Self, Error> {
        let encoded = lifecycle::codec::encode_open_binding(&binding, bounds)?;
        let extensions = Secret::new(crate::abi::mechanism::extensions::encode(&[(
            lifecycle::OPEN_BINDING,
            &encoded.0,
        )]));
        if extensions.0.len() > bounds.bytes as usize {
            return Err(Error::Bounds);
        }
        Ok(Self {
            binding,
            extensions,
        })
    }
    /// Requested native binding, containing identities but no plaintext credentials.
    pub fn binding(&self) -> &OpenBinding {
        &self.binding
    }
    /// Lend the stable versioned OPEN extension envelope.
    pub fn extensions(&self) -> Blob {
        Blob {
            ptr: self.extensions.0.as_ptr(),
            len: self.extensions.0.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        }
    }
}
impl std::fmt::Debug for OpenBindingBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenBindingBytes").finish_non_exhaustive()
    }
}

/// Compare session authority without exposing its protected native token.
pub fn same_upgrade<O>(left: &lifecycle::UpgradeRef<O>, right: &lifecycle::UpgradeRef<O>) -> bool {
    left.id == right.id && left.authority == right.authority
}
/// Match an OPEN request to the actual retained inspection result.
pub fn open_matches<O>(inspection: &lifecycle::Inspection<O>, binding: &OpenBinding) -> bool {
    use lifecycle::InspectionState;
    match binding {
        OpenBinding::Empty => {
            inspection.state == InspectionState::Empty && inspection.source.is_none()
        }
        OpenBinding::Current {
            source,
            admission_marker_digest,
        } => {
            use sha2::{Digest, Sha256};
            inspection.state == InspectionState::Current
                && inspection.source.as_ref() == Some(source)
                && inspection.admission_marker.as_ref().is_some_and(|marker| {
                    <[u8; 32]>::from(Sha256::digest(&marker.0)) == *admission_marker_digest
                })
        }
        OpenBinding::Recovery(_) => false,
    }
}
