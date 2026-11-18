// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cold code of `crate::export_pump`.

/// Boot: the MIN-3 export instance `name` did not open, in words naming why.
#[cold]
pub(crate) fn not_opened(name: &str, e: &crate::instance::OpenError) -> String {
    use crate::instance::OpenError;
    match e {
        OpenError::Refused { .. } => format!("export instance `{name}` did not open (refused)"),
        OpenError::Config { code, .. } => {
            format!("export instance `{name}` did not open (config refused, code {code})")
        }
        OpenError::Failed { code, .. } => {
            format!("export instance `{name}` did not open (failed, code {code})")
        }
        OpenError::Call(c) => format!("export instance `{name}` did not open ({c:?})"),
        OpenError::Unknown(_) => format!("export instance `{name}` did not open (unknown)"),
    }
}
