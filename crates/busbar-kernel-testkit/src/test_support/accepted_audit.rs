// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::audit_ring::AuditEntry;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use tokio::sync::oneshot;

struct Observer {
    action: String,
    resource: String,
    principal: String,
    send: oneshot::Sender<AuditEntry>,
}

static OBSERVERS: std::sync::LazyLock<Mutex<BTreeMap<u64, Observer>>> =
    std::sync::LazyLock::new(|| Mutex::new(BTreeMap::new()));
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// A scoped observation of one accepted live admin-audit entry. Dropping it cancels the
/// registration, including when its awaiting test is cancelled or reaches a liveness bound.
#[derive(Debug)]
pub struct AcceptedAdminAudit {
    id: u64,
    receive: oneshot::Receiver<AuditEntry>,
}

impl AcceptedAdminAudit {
    pub async fn accepted(mut self) -> Result<AuditEntry, oneshot::error::RecvError> {
        (&mut self.receive).await
    }
}

impl Drop for AcceptedAdminAudit {
    fn drop(&mut self) {
        OBSERVERS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
    }
}

pub fn observe_accepted_admin_entry(
    action: &str,
    resource: &str,
    principal: &str,
) -> AcceptedAdminAudit {
    busbar_kernel::audit::auditlog::install_accepted_entry_test_hook(published);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let (send, receive) = oneshot::channel();
    OBSERVERS.lock().unwrap_or_else(|e| e.into_inner()).insert(
        id,
        Observer {
            action: action.into(),
            resource: resource.into(),
            principal: principal.into(),
            send,
        },
    );
    AcceptedAdminAudit { id, receive }
}

fn published(entry: &AuditEntry) {
    let ready = {
        let mut observers = OBSERVERS.lock().unwrap_or_else(|e| e.into_inner());
        let ids: Vec<_> = observers
            .iter()
            .filter(|(_, observer)| {
                observer.action == entry.action
                    && observer.resource == entry.resource
                    && observer.principal == entry.principal
            })
            .map(|(id, _)| *id)
            .collect();
        ids.into_iter()
            .filter_map(|id| observers.remove(&id).map(|observer| observer.send))
            .collect::<Vec<_>>()
    };

    for send in ready {
        let _ = send.send(entry.clone());
    }
}
