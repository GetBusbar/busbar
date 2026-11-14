// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! busbar's one crypto API (CRYPTO-SEAM §2.3). Not implemented yet: the conformance suite below
//! pins what it must answer.

#![deny(unsafe_code)]

/// The crypto backend this binary was built with.
pub const BACKEND: &str = busbar_crypto_backend::NAME;

#[cfg(feature = "test-support")]
pub mod conformance;
