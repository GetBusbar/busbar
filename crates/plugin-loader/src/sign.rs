// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Artifact signing and verification, reexported from the standalone owner.
#[cfg(test)]
use crate::verification::Verifier;
#[cfg(test)]
use busbar_artifact_verifier::sign::test_support::*;
pub use busbar_artifact_verifier::sign::*;
#[cfg(test)]
use std::collections::BTreeMap;

#[cfg(test)]
#[path = "tests/sign_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/scoped_publisher_tests.rs"]
mod scoped_publisher_tests;

#[cfg(test)]
#[path = "tests/declares_reader_tests.rs"]
mod declares_reader_tests;

#[cfg(test)]
#[path = "tests/release_seal_tests.rs"]
mod release_seal_tests;

#[cfg(test)]
#[path = "tests/native_pack_sign_tests.rs"]
mod native_pack_sign_tests;
