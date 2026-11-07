// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Automatic upgrade and the single application readiness boundary.
pub mod bindings;
pub mod bootstrap;
pub mod continuation;
pub mod document_commit;
pub mod documents;
pub mod publication;
pub(crate) mod recovery;
pub mod spool;
