// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel services the core-resolved intents run on (IF §12.1, §12.11): what [`KernelIntents`] holds beside
//! its records, push queue and signals. A service not installed answers its fail-closed value (no grant, an
//! internal destination, a refused mint), never an unchecked yes.
//!
//! [`KernelIntents`]: super::port_intents::KernelIntents

use std::sync::Arc;

use super::plane_judge::PlaneJudge;
use crate::connections::CallerConnections;
use crate::plane_grants::{Entitlements, HostSigner, Tickets};

/// The services behind the intents. `Default` installs none.
#[derive(Clone, Default)]
pub struct Services {
    /// ENTITLE (§12.11).
    pub entitlements: Option<Arc<dyn Entitlements>>,
    /// JUDGE (§12.1).
    pub judge: Option<PlaneJudge>,
    /// MINT (§12.11).
    pub tickets: Option<Arc<dyn Tickets>>,
    /// SIGN (§12.11).
    pub signer: Option<Arc<dyn HostSigner>>,
    /// CONNECT (§12.12).
    pub connections: Option<Arc<dyn CallerConnections>>,
}
