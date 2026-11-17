// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The opened Store backend type. A Store is a MIN-3 image opened through the loader's
//! `Registry::open_store` (WP3: the door store axis is retired).

use std::sync::Arc;

use super::PersistenceBackend;

/// One opened backend; its instance facts are available through `info()`.
pub type OpenedBackend = Arc<dyn PersistenceBackend>;
