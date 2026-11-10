// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Neutral native Store preparation, retained upgrade sessions and source pages.
//! Native ownership never grants logical migration or serving authority by itself.

use super::{BackendInfo, DatasetId};
use crate::{redacted::Kernel, Secret};

/// Initial strict bootstrap request/response codec.
pub const VERSION: u32 = 1;
/// Opaque current-admission marker namespace; providers copy bytes, never interpret it.
pub const ADMISSION_NAMESPACE: [u8; 16] = *b"busbar.format1\0\0";
/// Opaque current-admission marker key.
pub const ADMISSION_KEY: &[u8] = b"active";
/// Exact OPEN extension carrying a verified current/recovery binding.
pub const OPEN_BINDING: &str = "busbar.store.bootstrap.open/1";
/// An opaque stable native identity.
pub type Id = [u8; 16];
/// A complete SHA256 identity.
pub type Digest = [u8; 32];

pub mod source;
pub use source::{
    DocumentSemantics, InterpretationBounds, SourceCodec, SourceReader, INTERPRETED_SOURCE,
};

/// Explicit aggregate allocation and page limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    /// Maximum row/table/selector items in a single bounded reply.
    pub items: u32,
    /// Maximum encoded request/reply and owned allocation bytes.
    pub bytes: u32,
}
/// Exact format axes; historical source physical values retain their identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Format {
    /// Registered owner discriminator.
    pub owner: Id,
    /// Actual physical format.
    pub physical: u32,
    /// Logical format interpreted by the migration owner.
    pub logical: u32,
    /// Exact encoded record format.
    pub codec: u32,
}
/// Current core target owner; native backends retain opaque records under this format.
pub const CORE_FORMAT_OWNER: Id = *b"busbar.core.v1\0\0";
/// Initial current-target format, shared with the compiled migration registry.
pub const CORE_FORMAT: Format = Format {
    owner: CORE_FORMAT_OWNER,
    physical: 1,
    logical: 1,
    codec: 1,
};
/// Actual native source identity observed without schema writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceIdentity {
    /// Actual native instance/database origin digest.
    pub native_anchor: Digest,
    /// Stable native dataset identity, independent of process-local session tokens.
    pub dataset: DatasetId,
    /// Exact source format, when the native marker is recognized.
    pub format: Option<Format>,
    /// Exact native catalogue fingerprint.
    pub catalogue_digest: Digest,
    /// Exact ordered column/type/layout fingerprint.
    pub layout_digest: Digest,
}
/// Native state, never inferred from a failed/empty query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectionState {
    /// Confirmed missing or empty native storage.
    Empty,
    /// Native current selector and admission marker are present.
    Current,
    /// A recognized historical physical source.
    Legacy(SourceReader),
    /// A durable native upgrade must be resumed.
    InProgress(SourceReader),
    /// Nonempty storage whose format has no supported native reader.
    Unsupported,
    /// Native ownership is currently held by another starter.
    Busy,
}
impl InspectionState {
    /// The mandatory source reader of a historical or unfinished native upgrade.
    pub fn reader(self) -> Option<SourceReader> {
        match self {
            Self::Legacy(reader) | Self::InProgress(reader) => Some(reader),
            _ => None,
        }
    }
}
/// Concrete native operations the inspected implementation can supply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeCapability {
    /// Read-only source snapshot and bounded physical pages.
    Snapshot,
    /// Persistent old-writer enforcement with actual native rechecks.
    PersistentFence,
    /// Existing durable native upgrade reconciliation.
    Resume,
    /// Inactive target generation routed through the four primitives.
    InactiveTarget,
    /// Verified current-format ordinary OPEN.
    CurrentOpen,
}
/// Read-only native inspection result.
#[derive(Debug)]
pub struct Inspection<O = Kernel> {
    /// Actual state.
    pub state: InspectionState,
    /// Identity of existing native storage; absent only for confirmed Empty.
    pub source: Option<SourceIdentity>,
    /// Exact opaque current logical/admission marker, interpreted by core.
    pub admission_marker: Option<Secret<Vec<u8>, O>>,
    /// Tables in canonical order, columns in original native declared order.
    pub catalogue: Vec<super::archive::Table>,
    /// Explicit native operations; none substitutes for live ownership checks.
    pub capabilities: Vec<NativeCapability>,
}
/// Retained native authority for one durable upgrade. Not a transferable lease.
#[derive(Debug)]
pub struct UpgradeRef<O = Kernel> {
    /// Durable upgrade identity.
    pub id: Id,
    /// Protected session-bound native authority, never operator-supplied approval.
    pub authority: Secret<Vec<u8>, O>,
}
impl<O> Clone for UpgradeRef<O> {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            authority: self.authority.clone(),
        }
    }
}
/// Actual retained source/target and durable native-step progress.
#[derive(Debug)]
pub struct Upgrade<O = Kernel> {
    /// Durable upgrade authority.
    pub reference: UpgradeRef<O>,
    /// Original inspected source identity.
    pub source: SourceIdentity,
    /// Retained immutable native snapshot identity.
    pub snapshot: Id,
    /// Migration-only inactive target facts.
    pub target: BackendInfo,
    /// Backend-owned DDL/physical step, not semantic migration progress.
    pub native_step: u64,
    /// Exact catalogue/snapshot inventory established after native enforcement.
    pub catalogue: Vec<super::archive::Table>,
}
/// Versioned native selectors. No SQL text or logical credential/accounting policy.
#[derive(Debug)]
pub enum SourceSelector<O = Kernel> {
    /// Interpret the complete retained source through its declared neutral codec.
    /// SourcePage's ordinary bounds still limit each encoded response page.
    Interpret {
        /// Exact reader declaration admitted before beginning the upgrade.
        reader: SourceReader,
        /// Explicit aggregate group/index budgets, independent of page size.
        bounds: InterpretationBounds,
    },
    /// Native table/cursor scan in original native key order.
    Scan {
        /// Catalogue table ordinal.
        table: u32,
    },
    /// Exact original native identity.
    Exact {
        /// Catalogue table ordinal.
        table: u32,
        /// Protected native key frame.
        key: Secret<Vec<u8>, O>,
    },
    /// Prefix of a declared native index; the implementation validates the ordinal.
    IndexPrefix {
        /// Catalogue table ordinal.
        table: u32,
        /// Native declared index ordinal.
        index: u32,
        /// Protected exact prefix frame.
        prefix: Secret<Vec<u8>, O>,
    },
}
/// One untouched native physical row.
#[derive(Debug)]
pub struct SourceRow<O = Kernel> {
    /// Catalogue table ordinal.
    pub table: u32,
    /// Original native identity frame, including original cell type bits.
    pub native_key: Secret<Vec<u8>, O>,
    /// Exact legacy_row bytes; expiry/type metadata remains in its native cells.
    pub value: Secret<Vec<u8>, O>,
}
/// A bounded source page, never a whole logical-group allocation.
#[derive(Debug)]
pub struct SourcePage<O = Kernel> {
    /// Retained immutable snapshot identity.
    pub snapshot: Id,
    /// Requested compiled physical family.
    pub family: Id,
    /// Original protected physical rows.
    pub rows: Vec<SourceRow<O>>,
    /// Exclusive protected continuation; absent means the selected stream completed.
    pub next: Option<Secret<Vec<u8>, O>>,
    /// Exact native source/snapshot content identity.
    pub source_digest: Digest,
    /// Streaming coverage commitment through this page.
    pub coverage_digest: Digest,
}
/// Native routing for the inactive target; only the loader mints its backend capability.
#[derive(Debug)]
pub struct TargetBinding<O = Kernel> {
    /// Original durable upgrade.
    pub upgrade: Id,
    /// Fixed target instance facts.
    pub info: BackendInfo,
    /// Protected generation/session binding consumed by the loader.
    pub binding: Secret<Vec<u8>, O>,
}
/// Fresh native enforcement observation over the retained source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fence {
    /// Original durable upgrade.
    pub upgrade: Id,
    /// Actual native source identity checked now.
    pub source: SourceIdentity,
    /// Actual installed native enforcement policy digest.
    pub enforcement_digest: Digest,
    /// Fresh native instance/session/transaction drain observation.
    pub observation_digest: Digest,
    /// Same retained immutable snapshot.
    pub snapshot: Id,
}
/// Native physical selection completed; only checkpoint-bound cold recovery may reopen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryReady {
    /// Original upgrade identity.
    pub upgrade: Id,
    /// Confirmed target dataset.
    pub target: DatasetId,
    /// Confirmed core activation receipt identity.
    pub activation_receipt_digest: Digest,
    /// Confirmed native target selector identity.
    pub selector_digest: Digest,
}
/// Requested ordinary/cold-recovery OPEN binding, checked against the retained session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenBinding {
    /// Confirmed empty store's shorter initialization route.
    Empty,
    /// Exact inspected current native identity and logical admission marker.
    Current {
        /// Original native source identity.
        source: SourceIdentity,
        /// Exact core marker identity.
        admission_marker_digest: Digest,
    },
    /// Only the identified checkpoint-bound cold-recovery owner, never serving readiness.
    Recovery(RecoveryReady),
}
/// Which confirmed core checkpoint the native owner must verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionPhase {
    /// Core activated the target for checkpoint-bound cold recovery.
    Activation,
    /// Core completed recovery/verification and the same backend may serve.
    Complete,
}
/// Atomic neutral witness stored with the same core checkpoint candidate/receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionMarker {
    /// Must equal VERSION.
    pub version: u32,
    /// Actual committed checkpoint phase, never only the request's phase tag.
    pub phase: CompletionPhase,
    /// Original durable native upgrade.
    pub upgrade: Id,
    /// Original source dataset retained by the session.
    pub source: DatasetId,
    /// Exact inactive target dataset.
    pub target: DatasetId,
    /// Exact core checkpoint address committed atomically beside this witness.
    pub checkpoint_address: super::Address,
    /// Hash of the exact checkpoint bytes committed in that candidate.
    pub checkpoint_value_digest: Digest,
}
/// The only marker address accepted by native Finish for this retained session.
pub fn completion_marker_address(upgrade: Id) -> super::Address {
    let mut key = Vec::with_capacity(24);
    key.extend_from_slice(b"upgrade/");
    key.extend_from_slice(&upgrade);
    super::Address {
        namespace: ADMISSION_NAMESPACE,
        key,
    }
}
/// Native-verifiable proof of an exact confirmed core checkpoint commit.
#[derive(Debug)]
pub struct ActivationReceipt<O = Kernel> {
    /// The exact retained candidate's original attempt identity.
    pub attempt: super::AttemptId,
    /// The exact confirmed candidate fingerprint.
    pub candidate_fingerprint: Digest,
    /// Exact original applied result read from the native receipt.
    pub original_result: Secret<Vec<u8>, O>,
    /// Target control/checkpoint address actually committed by core.
    pub checkpoint_address: super::Address,
    /// Exact current checkpoint bytes to verify without interpreting migration JSON.
    pub checkpoint_value_digest: Digest,
    /// Distinct native verification obligation, never inferred from a caller boolean.
    pub phase: CompletionPhase,
}
/// Final native authorization for the already-open recovered backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServingReady {
    /// Original checkpoint-bound recovery session.
    pub recovery: RecoveryReady,
    /// Exact confirmed Complete checkpoint identity verified natively.
    pub completed_checkpoint_digest: Digest,
}
/// Exact bootstrap operation retained across Pending, SHORT and unknown completion.
#[derive(Debug)]
pub enum Request<O = Kernel> {
    /// Read-only inspection before any native schema mutation.
    Inspect {
        /// Explicit output/allocation bounds.
        bounds: Bounds,
    },
    /// Claim or reconcile one durable native upgrade for the exact registered route.
    BeginOrResume {
        /// Original inspected identity.
        expected_source: SourceIdentity,
        /// Exact compiled semantic route.
        route_digest: Digest,
        /// Desired native/core target format.
        target_format: Format,
        /// Stable operation identity retained after unknown completion.
        operation_id: Id,
    },
    /// Read protected native physical rows from the retained immutable snapshot.
    SourcePage {
        /// Retained native authority.
        upgrade: UpgradeRef<O>,
        /// Exact retained snapshot.
        snapshot: Id,
        /// Compiled physical family.
        family: Id,
        /// Versioned native selector.
        selector: SourceSelector<O>,
        /// Original protected exclusive continuation.
        cursor: Option<Secret<Vec<u8>, O>>,
        /// Explicit row/allocation bounds.
        bounds: Bounds,
    },
    /// Obtain the inactive target's existing primitive backend routing.
    Target {
        /// Retained native authority.
        upgrade: UpgradeRef<O>,
    },
    /// Recheck live native enforcement and immutable source identity.
    CheckFence {
        /// Retained native authority.
        upgrade: UpgradeRef<O>,
    },
    /// Confirm core activation and idempotently finalize the physical selector.
    Finish {
        /// Retained native authority.
        upgrade: UpgradeRef<O>,
        /// Original confirmed core activation receipt bytes.
        activation_receipt: ActivationReceipt<O>,
    },
}
/// Definitive typed native result; uncertainty is never a false no-effect answer.
#[derive(Debug)]
pub enum Response<O = Kernel> {
    /// Read-only native inspection.
    Inspected(Inspection<O>),
    /// Retained or reconciled durable upgrade.
    Begun(Upgrade<O>),
    /// Bounded immutable physical source page.
    SourcePage(SourcePage<O>),
    /// Inactive primitive target routing.
    Target(TargetBinding<O>),
    /// Fresh native enforcement observation.
    Fence(Fence),
    /// Physical selector finalized for checkpoint-bound cold recovery only.
    RecoveryReady(RecoveryReady),
    /// Actual Complete checkpoint verified; same recovered backend may serve.
    ServingReady(ServingReady),
}
/// Content-free native preparation/upgrade failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Another owner is active; no authority acquired.
    Busy,
    /// Work remains retained in the actual ticket/session owner.
    Pending,
    /// Native nonempty format is unsupported.
    UnsupportedFormat,
    /// A required native operation cannot be supplied.
    MissingCapability,
    /// Native source/catalogue/snapshot or enforcement changed.
    SourceChanged,
    /// Malformed source, protocol, or durable control evidence.
    Corrupt,
    /// Explicit refusal before the requested native effect.
    Refused,
    /// Native connection unavailable; does not establish an empty source.
    Unavailable,
    /// Completion may have occurred; retain and reconcile the exact operation.
    Unknown,
    /// Explicit aggregate/page/allocation budget exceeded.
    Bounds,
}

/// Owned asynchronous preparation capabilities implemented only by the loader.
pub mod axis;
pub use axis::*;

impl<O> Clone for SourceSelector<O> {
    fn clone(&self) -> Self {
        match self {
            Self::Interpret { reader, bounds } => Self::Interpret {
                reader: *reader,
                bounds: *bounds,
            },
            Self::Scan { table } => Self::Scan { table: *table },
            Self::Exact { table, key } => Self::Exact {
                table: *table,
                key: key.clone(),
            },
            Self::IndexPrefix {
                table,
                index,
                prefix,
            } => Self::IndexPrefix {
                table: *table,
                index: *index,
                prefix: prefix.clone(),
            },
        }
    }
}
impl<O> Clone for ActivationReceipt<O> {
    fn clone(&self) -> Self {
        Self {
            attempt: self.attempt,
            candidate_fingerprint: self.candidate_fingerprint,
            original_result: self.original_result.clone(),
            checkpoint_address: self.checkpoint_address.clone(),
            checkpoint_value_digest: self.checkpoint_value_digest,
            phase: self.phase,
        }
    }
}
impl<O> Clone for Request<O> {
    fn clone(&self) -> Self {
        match self {
            Self::Inspect { bounds } => Self::Inspect { bounds: *bounds },
            Self::BeginOrResume {
                expected_source,
                route_digest,
                target_format,
                operation_id,
            } => Self::BeginOrResume {
                expected_source: expected_source.clone(),
                route_digest: *route_digest,
                target_format: *target_format,
                operation_id: *operation_id,
            },
            Self::SourcePage {
                upgrade,
                snapshot,
                family,
                selector,
                cursor,
                bounds,
            } => Self::SourcePage {
                upgrade: upgrade.clone(),
                snapshot: *snapshot,
                family: *family,
                selector: selector.clone(),
                cursor: cursor.clone(),
                bounds: *bounds,
            },
            Self::Target { upgrade } => Self::Target {
                upgrade: upgrade.clone(),
            },
            Self::CheckFence { upgrade } => Self::CheckFence {
                upgrade: upgrade.clone(),
            },
            Self::Finish {
                upgrade,
                activation_receipt,
            } => Self::Finish {
                upgrade: upgrade.clone(),
                activation_receipt: activation_receipt.clone(),
            },
        }
    }
}

/// Strict protected lifecycle request/response codecs.
pub mod codec;
