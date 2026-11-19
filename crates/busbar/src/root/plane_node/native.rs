// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Original DATA ownership in the same funded terminal book as legacy callers.

use std::sync::{Arc, Weak};

use busbar_contract::caps::{Abort, CallId, Outcome, ReasonCode, StepName};
use busbar_contract::response_delivery::{DeliverySnapshot, DeliveryTerminal};
use busbar_contract::storage::StorageCredit;
use busbar_contract::UnitKey;
use busbar_kernel::auth::native_data::{NativeDataAllocation, NativeDataPending};
use busbar_kernel::inbound::native::StreamOwner;
use busbar_kernel::limits::process_admission::AdmissionClass;
use busbar_kernel::plane_driver::port::Unit;
use busbar_kernel::plane_driver::port_billing::{NativeOrdinaryTerminalSlot, PortBilling};
use busbar_kernel::teller::native_data_audit::{NativeAuditOwner, NativeAuditTerminal};

use super::{Node, NodeEndPost, RetainedState, RetainedUnit};
use crate::root::listener_native::{InputError, NativeCarrierRetired};

/// What [`Node::install_native`] hands back: the entry's handle, its unit and its terminal slot.
type NativeInstalled = (NativeNodeHandle, Unit, Arc<NativeOrdinaryTerminalSlot>);
/// Why [`Node::install_native`] refused, with the handle when the entry was already made.
type NativeInstallRefused = (InputError, Option<NativeNodeHandle>);

pub(super) struct NativeUnit {
    // Live until the work/delivery join freezes it; then `terminal` keeps the same owner.
    owner: Option<NativeAuditOwner>,
    terminal: Option<NativeAuditTerminal>,
    // Physical retirement proof: the delivered terminal snapshot, or W04's carrier receipt.
    delivered: bool,
    frozen: Option<crate::root::durability::FrozenNativeAudit>,
    journal_confirmed: bool,
    stream: Arc<StreamOwner>,
    post: Arc<NodeEndPost>,
    pending: Option<Arc<NativeDataPending>>,
    carrier: Option<NativeCarrierRetired>,
    staged: Option<crate::root::durability::NativeStagedAudit>,
    original_receipt: Option<OriginalLineReceipt>,
    // Dedicated original-notary retention credit; never substitutes for book backing.
    receipt_credit: Option<StorageCredit>,
    // The original funded ordinary slot; its Open transfers only through this Node owner.
    ordinary: Arc<NativeOrdinaryTerminalSlot>,
    billing: PortBilling,
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
            let owned = native
                .owner
                .as_ref()
                .is_some_and(|owner| pending.owned_by(owner));
            if native.pending.is_some() || !owned {
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
    ) -> Result<NativeInstalled, NativeInstallRefused> {
        let failure = |error| (error, None);
        // The book that will own this entry's fee observer receives original captures: it is the
        // fee-debt owner every root-built GovState is given (`fee_debt_owner`).
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
        // Funded from the original request before the monetary gate; refusal precedes admission.
        let ordinary = NativeOrdinaryTerminalSlot::reserve(
            allocation.context(),
            &owner.binding().request().storage(),
        )
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
                    owner: Some(owner),
                    terminal: None,
                    delivered: false,
                    frozen: None,
                    journal_confirmed: false,
                    stream,
                    post,
                    pending: None,
                    carrier: None,
                    staged: None,
                    original_receipt: None,
                    receipt_credit: Some(receipt_credit),
                    ordinary: ordinary.clone(),
                    billing: billing.clone(),
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
        let owner = native
            .owner
            .as_mut()
            .expect("the just-installed entry holds its live owner");
        owner
            .enter(&self.inflight, &self.door, arrived.ms())
            .map_err(|_| held(InputError::Invalid))?;
        let unit = billing
            .allocated_data_audited(allocation, owner, classes)
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
            owner.context().origin,
        );
        if let Some(slot) = owner.slot() {
            self.ticket_custody.bind_source(owner.context(), slot);
        }
        Ok((handle, unit, ordinary))
    }
}

use crate::root::durability::notary::original::{
    OriginalLineReceipt, OriginalPageCursor, OriginalPageReceipt, OriginalPageTarget, PageDelivery,
    PageFunding,
};

impl Node {
    pub(crate) fn bind_native_notary(self: &Arc<Self>) -> Result<(), &'static str> {
        self.book
            .get()
            .ok_or("native notary requires original book")?
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .head
            .register_original_receiver(Arc::downgrade(&self.lost))
    }
}

/// What the original notary reads and writes of one retained entry.
struct OriginalFields<'a> {
    staged: &'a Option<crate::root::durability::NativeStagedAudit>,
    receipt: &'a mut Option<OriginalLineReceipt>,
    credit: &'a mut Option<StorageCredit>,
}

fn original_fields(state: &mut RetainedState) -> Option<OriginalFields<'_>> {
    match state {
        RetainedState::Native(native) => Some(OriginalFields {
            staged: &native.staged,
            receipt: &mut native.original_receipt,
            credit: &mut native.receipt_credit,
        }),
        #[cfg(test)]
        RetainedState::Original {
            staged,
            receipt,
            credit,
        } => Some(OriginalFields {
            staged: &*staged,
            receipt,
            credit,
        }),
        _ => None,
    }
}

/// One funding slice of the charged table for the original notary. No subscriber or retry
/// queue is added.
pub(crate) fn fund_original_page(
    retained: &super::RetainedBook,
    target: &OriginalPageTarget,
    bytes: usize,
    cursor: Option<OriginalPageCursor>,
) -> PageFunding {
    let mut guard = retained
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(book) = guard.as_mut() else {
        return PageFunding::Refused(cursor);
    };
    let mut position = cursor.unwrap_or_else(|| OriginalPageCursor {
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
        let Some(fields) = original_fields(&mut entry.state) else {
            continue;
        };
        let Some(staged) = fields.staged else {
            continue;
        };
        if !target.covers(staged) {
            continue;
        }
        let Some(held) = fields.credit.as_ref() else {
            continue;
        };
        if held.len() < bytes {
            return PageFunding::Refused(Some(position));
        }
        return PageFunding::Reserved(
            fields.credit.take().expect("validated retained credit"),
            position.upper,
        );
    }
    PageFunding::Pending(position)
}

/// One delivery slice of the charged table for the original notary.
pub(crate) fn deliver_original_page(
    retained: &super::RetainedBook,
    page: &OriginalPageReceipt,
    cursor: Option<OriginalPageCursor>,
) -> PageDelivery {
    let mut guard = retained
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
        let Some(fields) = original_fields(&mut entry.state) else {
            continue;
        };
        let Some(staged) = fields.staged else {
            continue;
        };
        if let Some(receipt) = page.bind(staged) {
            if fields
                .receipt
                .as_ref()
                .is_some_and(|held| !held.confirms(staged))
            {
                return PageDelivery::Refused;
            }
            *fields.receipt = Some(receipt);
        }
    }
    PageDelivery::Pending(position)
}

/// HELD (adopted ordinary receipt r2): the original per-fee Applied producer is unresolved and
/// under separate review. No checkpoint receipt, FeeAccount completion or global zero may stand
/// in for it, so an admitted native entry stays installed until that producer exists.
const ORIGINAL_FEE_APPLIED_PRODUCER: bool = false;

/// THE MONEY JOIN of one native entry's retirement, read under the entry lock: the facts an
/// admitted entry must hold before it may leave the Node book. An entry that was never admitted
/// holds no money and has nothing to join.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct MoneyJoin {
    /// The entry's terminal carries an admission: money was opened for it.
    pub(super) admitted: bool,
    /// The ordinary checkpoint's removal was acknowledged by the Store
    /// (`PortBilling::ordinary_checkpoint_confirmed`).
    pub(super) checkpoint_confirmed: bool,
    /// Every original fee target is Applied or honestly CancelledBeforeSend
    /// (`NativeOrdinaryTerminalSlot::fee_join_complete`, FEE-DEBT r1).
    pub(super) fee_join_complete: bool,
}

impl MoneyJoin {
    /// Whether the money side lets the entry retire.
    pub(super) fn complete(self) -> bool {
        if !self.admitted {
            return true;
        }
        self.checkpoint_confirmed && ORIGINAL_FEE_APPLIED_PRODUCER && self.fee_join_complete
    }
}

/// The adopted bound on candidates one native pulse examines, irrelevant entries included.
pub(crate) const NATIVE_PULSE_CANDIDATES: usize = 64;

impl NativeNodeHandle {
    /// Registered output: its genuine terminal reader snapshot is the physical retirement proof.
    /// A successfully delivered stream retires at delivery and receives no carrier notice.
    pub(crate) fn delivered(
        &self,
        snapshot: &DeliverySnapshot,
        work_ran: bool,
        work_failed: bool,
    ) -> Result<(), InputError> {
        let outcome = match snapshot.terminal.as_ref().ok_or(InputError::Invalid)? {
            DeliveryTerminal::Complete if work_ran && !work_failed => Outcome::Completed,
            DeliveryTerminal::Complete => {
                Outcome::Failed(StepName::Route, ReasonCode::DestinationUnreachable)
            }
            DeliveryTerminal::Failed(_) => Outcome::Aborted(Abort::Kernel {
                reason: ReasonCode::ClientGone,
            }),
        };
        self.with_native(|native| {
            native.freeze_terminal(outcome, snapshot.first_payload_written)?;
            native.delivered = true;
            Ok(())
        })
    }

    /// Output that never registered: W04's opaque carrier receipt (`carrier_retired`) plus the
    /// joined Task is the physical proof. No payload reached the client.
    pub(crate) fn unregistered(&self, work_ran: bool, work_failed: bool) -> Result<(), InputError> {
        let outcome = if work_failed || !work_ran {
            Outcome::Failed(StepName::Route, ReasonCode::DestinationUnreachable)
        } else {
            Outcome::Aborted(Abort::Kernel {
                reason: ReasonCode::ClientGone,
            })
        };
        self.with_native(|native| native.freeze_terminal(outcome, false))
    }
}

impl NativeUnit {
    /// The first terminal election freezes the original owner; later callers cannot replace it.
    fn freeze_terminal(&mut self, outcome: Outcome, first_payload: bool) -> Result<(), InputError> {
        if self.terminal.is_some() {
            return Ok(());
        }
        let owner = self.owner.take().ok_or(InputError::Invalid)?;
        match owner.into_terminal(outcome, first_payload) {
            Ok(terminal) => {
                self.terminal = Some(terminal);
                Ok(())
            }
            Err((owner, _)) => {
                self.owner = Some(owner);
                Err(InputError::Invalid)
            }
        }
    }

    fn physical_retired(&self) -> bool {
        self.delivered || self.carrier.is_some()
    }

    /// The original money owner's report, borrowed from the transferred ordinary terminal.
    /// Lines are named by the Open's own meter classes; nothing is repriced or re-admitted.
    fn ordinary_report(&self) -> Option<super::Report> {
        let busbar_kernel::plane_driver::UsageView::Legacy {
            lane,
            attribution,
            usage,
        } = self.ordinary.ordinary_usage()?
        else {
            return None;
        };
        let classes = self.ordinary.ordinary_classes()?;
        let mut usage_units = std::collections::BTreeMap::new();
        for (class, sum) in usage.by_class() {
            let Some(name) = classes.get(class as usize) else {
                continue;
            };
            let count = sum?;
            if count.is_zero() {
                continue;
            }
            let total = usage_units
                .entry(name.clone())
                .or_insert(busbar_contract::Count::ZERO);
            *total = total.checked_add(count).ok()?;
        }
        Some(super::Report {
            usage: busbar_contract::billing::ExactUsage { usage_units },
            // The native ordinary route admits with no plane fee units.
            fee_count: 0,
            lane,
            attribution,
        })
    }
}

fn native_mut(
    book: &mut Option<super::terminal_book::TerminalBook>,
    class: AdmissionClass,
    key: UnitKey,
    call: CallId,
) -> Option<&mut NativeUnit> {
    let entry = book.as_mut()?.get_mut(class, key)?;
    if entry.call != call {
        return None;
    }
    match &mut entry.state {
        RetainedState::Native(native) => Some(native),
        _ => None,
    }
}

impl Node {
    /// One bounded native pulse driven by the retained process upkeep. It examines at most the
    /// adopted 64 candidates, resuming from `cursor` across pulses; no retry queue or timer.
    pub(crate) async fn drive_native(&self, cursor: &mut Option<u64>) -> usize {
        let mut candidates = [None; NATIVE_PULSE_CANDIDATES];
        {
            let guard = self
                .lost
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(book) = guard.as_ref() else {
                return 0;
            };
            let upper = book.max_key();
            for candidate in &mut candidates {
                let Some((class, key)) = book.next(*cursor, upper) else {
                    *cursor = None;
                    break;
                };
                *cursor = Some(key.get());
                if let Some(entry) = book.get(class, key) {
                    if matches!(entry.state, RetainedState::Native(_)) {
                        *candidate = Some((class, key, entry.call));
                    }
                }
            }
        }
        if candidates.iter().all(Option::is_none) {
            return 0;
        }
        let Some(durability) = self.book.get().cloned() else {
            return 0;
        };
        let mut retired = 0;
        for (class, key, call) in candidates.into_iter().flatten() {
            if self.advance_native(&durability, class, key, call).await {
                retired += 1;
            }
        }
        retired
    }

    /// Advance one original entry. Every failure leaves it installed with its exact custody;
    /// it is rejoined by class, key and original call after each unlocked step.
    async fn advance_native(
        &self,
        durability: &Arc<std::sync::Mutex<crate::root::durability::Durability>>,
        class: AdmissionClass,
        key: UnitKey,
        call: CallId,
    ) -> bool {
        // Money transfer, frozen inputs and journal stage: synchronous, under the entry lock.
        let unconfirmed = {
            let mut guard = self
                .lost
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(native) = native_mut(&mut guard, class, key, call) else {
                return false;
            };
            let Some(terminal) = native.terminal.as_ref() else {
                return false;
            };
            let admitted = terminal.admission().is_some();
            if admitted {
                // Lock order Node entry -> slot -> money -> checkpoint. Failure retains intent.
                let _ = native.billing.drive_ordinary_terminal(&native.ordinary);
            }
            if native.frozen.is_none() && native.staged.is_none() {
                let report = if admitted {
                    let Some(report) = native.ordinary_report() else {
                        return false;
                    };
                    Some(report)
                } else {
                    None
                };
                let facts = native.post.lock(key);
                let Some(open) = facts.get(&key) else {
                    return false;
                };
                match crate::root::durability::FrozenNativeAudit::prepare(
                    (),
                    durability,
                    terminal.pass(),
                    |_| self.freeze_native_inputs(terminal, open, report.as_ref()),
                ) {
                    Ok((frozen, ())) => native.frozen = Some(frozen),
                    Err(refused) => {
                        tracing::error!(unit = key.get(), why = ?refused.why,
                            "native audit input refused; original custody retained");
                        return false;
                    }
                }
            }
            if native.staged.is_none() {
                let Some(frozen) = native.frozen.as_ref() else {
                    return false;
                };
                if crate::root::durability::Durability::stage_native(
                    durability,
                    frozen,
                    terminal.pass(),
                    &self.durability_token,
                    &mut native.staged,
                )
                .is_err()
                {
                    return false;
                }
            }
            if native.journal_confirmed {
                None
            } else {
                native.staged.clone()
            }
        };
        // Drive only the retained original journal run, outside every lock.
        if let Some(staged) = unconfirmed {
            if staged.confirm_journal().await.is_err() {
                return false;
            }
            let mut guard = self
                .lost
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(native) = native_mut(&mut guard, class, key, call) else {
                return false;
            };
            if !native
                .staged
                .as_ref()
                .is_some_and(|held| held.line() == staged.line())
            {
                return false;
            }
            native.journal_confirmed = true;
        }
        // Transferred fee obligations resolve against their exact pinned owners, outside locks.
        let money_owner = {
            let mut guard = self
                .lost
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(native) = native_mut(&mut guard, class, key, call) else {
                return false;
            };
            (native.ordinary.clone(), native.billing.clone())
        };
        money_owner.1.resolve_fee_transfers(&money_owner.0).await;
        // Every original join, then the single retirement of this exact entry.
        let removed = {
            let mut guard = self
                .lost
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(native) = native_mut(&mut guard, class, key, call) else {
                return false;
            };
            let Some(terminal) = native.terminal.as_ref() else {
                return false;
            };
            let admitted = terminal.admission().is_some();
            let money = MoneyJoin {
                admitted,
                checkpoint_confirmed: admitted
                    && native
                        .billing
                        .ordinary_checkpoint_confirmed(&native.ordinary)
                        .unwrap_or(false),
                fee_join_complete: admitted && native.ordinary.fee_join_complete(),
            }
            .complete();
            let notary = native
                .staged
                .as_ref()
                .zip(native.original_receipt.as_ref())
                .is_some_and(|(staged, receipt)| receipt.confirms(staged));
            if !(money && notary && native.journal_confirmed && native.physical_retired()) {
                return false;
            }
            if native
                .terminal
                .as_mut()
                .is_none_or(|terminal| terminal.complete(&self.gauge).is_err())
            {
                return false;
            }
            guard.as_mut().and_then(|book| book.remove(class, key))
        };
        // Releases happen after the book lock; the original facts retire with the entry.
        if let Some(RetainedUnit {
            state: RetainedState::Native(native),
            ..
        }) = removed
        {
            native.post.close(key);
            drop(native);
        }
        true
    }
}

use busbar_kernel::governance::fee_debt::{
    FeeAssociation, FeeCapture, FeeCursor, FeeDebtAssociate, ASSOCIATION_CANDIDATES,
};

/// FEE-DEBT r1: the original observer owner. One slice examines at most the adopted 64
/// candidates within the capture's finite UnitKey horizon; it performs no Store I/O and is
/// entered by the flusher only after every budget, money and checkpoint lock is released.
impl FeeDebtAssociate for Node {
    fn associate(&self, capture: &Arc<FeeCapture>, cursor: FeeCursor) -> FeeAssociation {
        let guard = self
            .lost
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(book) = guard.as_ref() else {
            return FeeAssociation::Complete;
        };
        let upper = cursor.upper.unwrap_or_else(|| book.max_key());
        let mut last = cursor.last;
        for _ in 0..ASSOCIATION_CANDIDATES {
            let Some((class, key)) = book.next(last, upper) else {
                return FeeAssociation::Complete;
            };
            last = Some(key.get());
            if let Some(RetainedUnit {
                state: RetainedState::Native(native),
                ..
            }) = book.get(class, key)
            {
                native.ordinary.offer_fee_capture(capture);
            }
        }
        FeeAssociation::Pending(FeeCursor {
            last,
            upper: Some(upper),
        })
    }
}

/// The process Node book as the original fee-debt observer owner, weakly: what every GovState the
/// composition root builds is given (`RootRules::fee_debt_owner`).
pub(crate) fn fee_debt_owner() -> std::sync::Weak<dyn FeeDebtAssociate> {
    let owner: Arc<dyn FeeDebtAssociate> = super::node();
    Arc::downgrade(&owner)
}

/// A real retained table for the original notary's tests: reserved entries and originals.
#[cfg(test)]
pub(crate) mod retained_fixture {
    use std::sync::{Arc, Mutex};

    use busbar_contract::storage::{StorageCredit, StorageSource};
    use busbar_contract::UnitKey;
    use busbar_kernel::limits::process_admission::AdmissionClass;

    use super::super::terminal_book::TerminalBook;
    use super::super::{RetainedBook, RetainedState, RetainedUnit};
    use crate::root::durability::notary::original::OriginalLineReceipt;
    use crate::root::durability::NativeStagedAudit;

    pub(crate) struct Retained {
        pub(crate) book: Arc<RetainedBook>,
        kernel: busbar_kernel::teller::Kernel,
    }

    impl Retained {
        /// An empty table whose backing is charged to `source`.
        pub(crate) fn new(source: StorageSource) -> Self {
            Self {
                book: Arc::new(RetainedBook(Mutex::new(Some(TerminalBook::new(
                    source.clone(),
                    source,
                ))))),
                kernel: crate::root::kernel::new_kernel(),
            }
        }

        fn insert(&self, key: u64, state: RetainedState) {
            let unit = RetainedUnit {
                call: self.kernel.next_call(),
                state,
            };
            let inserted = self.book.lock().unwrap().as_mut().unwrap().insert(
                AdmissionClass::Data,
                UnitKey::new(key),
                unit,
            );
            assert!(inserted.is_ok(), "the fixture table refused key {key}");
        }

        /// A reserved entry: a candidate the scans count and skip.
        pub(crate) fn reserve(&self, key: u64) {
            self.insert(key, RetainedState::Reserved);
        }

        /// An original as `install_native` and staging leave it: staged, funded, no receipt.
        pub(crate) fn original(&self, key: u64, staged: NativeStagedAudit, credit: StorageCredit) {
            self.insert(
                key,
                RetainedState::Original {
                    staged: Some(staged),
                    receipt: None,
                    credit: Some(credit),
                },
            );
        }

        /// The receipt the notary delivered to the original at `key`.
        pub(crate) fn receipt(&self, key: u64) -> Option<OriginalLineReceipt> {
            let guard = self.book.lock().unwrap();
            match &guard
                .as_ref()?
                .get(AdmissionClass::Data, UnitKey::new(key))?
                .state
            {
                RetainedState::Original { receipt, .. } => receipt.clone(),
                _ => None,
            }
        }

        /// Whether the original at `key` still holds its retention credit.
        pub(crate) fn holds_credit(&self, key: u64) -> bool {
            let guard = self.book.lock().unwrap();
            guard
                .as_ref()
                .and_then(|book| book.get(AdmissionClass::Data, UnitKey::new(key)))
                .is_some_and(|unit| {
                    matches!(
                        &unit.state,
                        RetainedState::Original {
                            credit: Some(_),
                            ..
                        }
                    )
                })
        }
    }
}

#[cfg(test)]
#[path = "native_retire_tests.rs"]
mod retire_tests;
