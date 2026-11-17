// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Original DATA ownership in the same funded terminal book as legacy callers.

use std::sync::{Arc, Weak};

use busbar_contract::caps::CallId;
use busbar_contract::storage::StorageCredit;
use busbar_contract::UnitKey;
use busbar_kernel::auth::native_data::{NativeDataAllocation, NativeDataPending};
use busbar_kernel::inbound::native::StreamOwner;
use busbar_kernel::limits::process_admission::AdmissionClass;
use busbar_kernel::plane_driver::port::Unit;
use busbar_kernel::plane_driver::port_billing::PortBilling;
use busbar_kernel::teller::native_data_audit::NativeAuditOwner;

use super::{Node, NodeEndPost, RetainedState, RetainedUnit};
use crate::root::listener_native::{InputError, NativeCarrierRetired};

pub(super) struct NativeUnit {
    owner: NativeAuditOwner,
    stream: Arc<StreamOwner>,
    post: Arc<NodeEndPost>,
    pending: Option<Arc<NativeDataPending>>,
    carrier: Option<NativeCarrierRetired>,
    staged: Option<crate::root::durability::NativeStagedAudit>,
    original_receipt: Option<OriginalLineReceipt>,
    // Dedicated original-notary retention credit; never substitutes for book backing.
    receipt_credit: Option<StorageCredit>,
}

/// A loan to one installed original. It neither owns Node nor creates a second entry.
#[derive(Clone)]
pub(crate) struct NativeNodeHandle {
    node: Weak<Node>,
    class: AdmissionClass,
    key: UnitKey,
    call: CallId,
}

impl NativeNodeHandle {
    fn with_native<T>(
        &self,
        action: impl FnOnce(&mut NativeUnit) -> Result<T, InputError>,
    ) -> Result<T, InputError> {
        let node = self.node.upgrade().ok_or(InputError::Invalid)?;
        let mut book = node
            .lost
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = book
            .as_mut()
            .and_then(|book| book.get_mut(self.class, self.key))
            .ok_or(InputError::Invalid)?;
        if entry.call != self.call {
            return Err(InputError::Invalid);
        }
        let RetainedState::Native(native) = &mut entry.state else {
            return Err(InputError::Invalid);
        };
        action(native)
    }

    pub(crate) fn carrier_retired(&self, receipt: NativeCarrierRetired) -> Result<(), InputError> {
        self.with_native(|native| {
            if !Arc::ptr_eq(&native.stream, receipt.owner()) {
                return Err(InputError::Invalid);
            }
            if native.carrier.is_none() {
                native.carrier = Some(receipt);
            }
            Ok(())
        })
    }

    pub(crate) fn bind_pending(&self, pending: Arc<NativeDataPending>) -> Result<(), InputError> {
        self.with_native(|native| {
            if native.pending.is_some() || !native.owner.invocation().same_unit(pending.context()) {
                return Err(InputError::Invalid);
            }
            native.pending = Some(pending);
            Ok(())
        })
    }
}

impl Node {
    pub(crate) fn native_pending(&self) -> usize {
        self.lost
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map_or(0, |book| {
                book.values()
                    .filter(|entry| matches!(entry.state, RetainedState::Native(_)))
                    .count()
            })
    }

    /// Install original physical/audit ownership before opening the monetary callback gate.
    pub(crate) fn install_native(
        self: &Arc<Self>,
        allocation: &mut NativeDataAllocation,
        stream: Arc<StreamOwner>,
        post: Arc<NodeEndPost>,
        billing: &PortBilling,
        classes: Arc<[String]>,
    ) -> Result<(NativeNodeHandle, Unit), (InputError, Option<NativeNodeHandle>)> {
        let failure = |error| (error, None);
        let ready = self
            .book
            .get()
            .ok_or_else(|| failure(InputError::Invalid))?
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .head
            .original_ready()
            .ok_or_else(|| failure(InputError::Invalid))?;
        if !ready.is_ready() {
            return Err(failure(InputError::Invalid));
        }
        let owner = allocation
            .take_audit_registration()
            .map_err(|_| failure(InputError::Invalid))?
            .bind(self.kernel.clone())
            .map_err(|_| failure(InputError::Invalid))?;
        if !owner.binding().owns_stream(&stream) {
            return Err(failure(InputError::Invalid));
        }
        let receipt_credit = owner
            .binding()
            .request()
            .storage()
            .try_reserve(ready.retention_bytes())
            .map_err(|_| failure(InputError::Capacity))?;
        let class = owner.binding().request().class();
        let key = owner.context().key;
        let call = owner.context().call;
        let arrived = self
            .checked_arrived()
            .map_err(|_| failure(InputError::Invalid))?;
        let handle = NativeNodeHandle {
            node: Arc::downgrade(self),
            class,
            key,
            call,
        };
        let mut book = self
            .lost
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let book = book.as_mut().ok_or_else(|| failure(InputError::Invalid))?;
        book.insert(
            class,
            key,
            RetainedUnit {
                call,
                state: RetainedState::Native(NativeUnit {
                    owner,
                    stream,
                    post,
                    pending: None,
                    carrier: None,
                    staged: None,
                    original_receipt: None,
                    receipt_credit: Some(receipt_credit),
                }),
            },
        )
        .map_err(|_| failure(InputError::Capacity))?;
        let RetainedState::Native(native) = &mut book
            .get_mut(class, key)
            .expect("just installed original entry")
            .state
        else {
            unreachable!()
        };
        let held = |error| (error, Some(handle.clone()));
        native
            .owner
            .enter(&self.inflight, &self.door, arrived.ms())
            .map_err(|_| held(InputError::Invalid))?;
        let unit = billing
            .allocated_data_audited(allocation, &native.owner, classes)
            .map_err(|_| held(InputError::Invalid))?;
        let principal = allocation
            .context()
            .principal()
            .ok_or_else(|| held(InputError::Invalid))?;
        native.post.open(
            key,
            busbar_contract::caps::PrincipalId::new(&principal.id),
            arrived,
            None,
        );
        native.post.checkpoint_identity(
            key,
            busbar_contract::caps::OpClassId::new("data"),
            native.owner.context().origin,
        );
        if let Some(slot) = native.owner.slot() {
            self.ticket_custody
                .bind_source(native.owner.context(), slot);
        }
        Ok((handle, unit))
    }
}

use crate::root::durability::notary::original::{
    OriginalLineReceipt, OriginalPageCursor, OriginalPageReceipt, OriginalPageReceiver,
    OriginalPageTarget, PageDelivery, PageFunding,
};

impl Node {
    pub(crate) fn bind_native_notary(self: &Arc<Self>) -> Result<(), &'static str> {
        let receiver: Arc<dyn OriginalPageReceiver> = self.clone();
        self.book
            .get()
            .ok_or("native notary requires original book")?
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .head
            .register_original_receiver(Arc::downgrade(&receiver))
    }
}

impl OriginalPageReceiver for Node {
    fn fund_original_page(
        &self,
        target: &OriginalPageTarget,
        bytes: usize,
        cursor: Option<OriginalPageCursor>,
    ) -> PageFunding {
        let mut guard = self
            .lost
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(book) = guard.as_mut() else {
            return PageFunding::Refused(cursor);
        };
        let mut position = cursor.unwrap_or(OriginalPageCursor {
            last: None,
            upper: book.max_key(),
        });
        // This newly adopted bound counts every examined entry, including legacy/nonmembers.
        for _ in 0..64 {
            let Some((class, key)) = book.next(position.last, position.upper) else {
                return PageFunding::Empty(position.upper);
            };
            position.last = Some(key.get());
            let Some(entry) = book.get_mut(class, key) else {
                return PageFunding::Refused(Some(position));
            };
            let RetainedState::Native(native) = &mut entry.state else {
                continue;
            };
            let Some(staged) = &native.staged else {
                continue;
            };
            if !target.covers(staged) {
                continue;
            }
            let Some(credit) = native.receipt_credit.as_ref() else {
                continue;
            };
            if credit.len() < bytes {
                return PageFunding::Refused(Some(position));
            }
            return PageFunding::Reserved(
                native
                    .receipt_credit
                    .take()
                    .expect("validated retained credit"),
                position.upper,
            );
        }
        PageFunding::Pending(position)
    }

    fn deliver_original_page(
        &self,
        page: &OriginalPageReceipt,
        cursor: Option<OriginalPageCursor>,
    ) -> PageDelivery {
        let mut guard = self
            .lost
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(book) = guard.as_mut() else {
            return PageDelivery::Refused;
        };
        // The producer supplies its original captured horizon, even on first delivery.
        let Some(mut position) = cursor else {
            return PageDelivery::Refused;
        };
        for _ in 0..64 {
            let Some((class, key)) = book.next(position.last, position.upper) else {
                return PageDelivery::Complete;
            };
            position.last = Some(key.get());
            let Some(entry) = book.get_mut(class, key) else {
                return PageDelivery::Refused;
            };
            let RetainedState::Native(native) = &mut entry.state else {
                continue;
            };
            let Some(staged) = &native.staged else {
                continue;
            };
            if let Some(receipt) = page.bind(staged) {
                if native
                    .original_receipt
                    .as_ref()
                    .is_some_and(|held| !held.confirms(staged))
                {
                    return PageDelivery::Refused;
                }
                native.original_receipt = Some(receipt);
            }
        }
        PageDelivery::Pending(position)
    }
}
