// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cold code of `crate::durable_documents`.

/// Boot: a startup document commit names its temporary file.
#[cfg(unix)]
#[cold]
pub(crate) fn temporary_name(random: &[u8; 16]) -> Result<std::ffi::CString, std::ffi::NulError> {
    std::ffi::CString::new(format!(".busbar-document-{}.tmp", hex::encode(random)))
}
