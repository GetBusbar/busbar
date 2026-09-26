//! The plane kind: what bytes mean. A plane names a transport only as a claim, never holds a
//! connection, names no unit or other plane except through a nested destination, and returns
//! facts and locators only — never an amount, a decision, a credential, a price or a scheme
//! outside its claim. Pure over its inputs; no default bodies (see `docs/design/contract-notes.md`).

use crate::bounded::{Facts, Ir, ScratchBytes};
use crate::dest::{EgressBody, RoutePlan, VerifiedDestination};
use crate::grammar::Claim;
use crate::ids::{AdminVerbId, CorrelationRef, MeterClassDecl, OpClassId, RecordSchemaId};
use crate::plugin::Plugin;
use crate::unit::{
    AdmitFacts, AuditFacts, Ctx, FinishClass, Refusal, ScopeFacts, Unit, UnitEnd, UsageLocators,
};
use crate::wire::{Decode, DiscardCode, Encode, Frame, FrameCursor};
use std::any::Any;

/// Everything a plane declares about itself.
///
/// All of it is a constant, because all of it is read at registration and sealed into policy. A
/// plane cannot vary its own declarations at run time; if it could, the claims a boot proved
/// non-overlapping would stop being the claims that are in force.
pub trait PlaneMeta {
    /// The plane's registry key.
    const KEY: &'static str;
    /// The claims this plane makes over arriving bytes.
    const CLAIMS: &'static [Claim];
    /// The operation classes this plane's units can be.
    const OP_CLASSES: &'static [OpClassId];
    /// The meter classes this plane meters, each with its family, direction and default divisor.
    const METER_CLASSES: &'static [MeterClassDecl];
    /// The session fact keys this plane writes.
    const SESSION_FACTS: &'static [&'static str];
    /// The content fact keys this plane produces.
    const CONTENT_FACTS: &'static [&'static str];
    /// The record schemas this plane keeps kernel-held durable records under.
    const RECORD_SCHEMAS: &'static [RecordSchemaId];
    /// The read-only introspection verbs this plane answers.
    const INTROSPECTION_VERBS: &'static [AdminVerbId];
    /// The fact key that means "this frame supersedes the open one", where the dialect has one.
    const INTERRUPT_FACT: Option<&'static str>;
    /// The fact key that paces the kernel's outbound write path, where the dialect has one.
    const EGRESS_PACING_FACT: Option<&'static str>;
    /// The schema of this plane's own configuration block.
    const CONFIG_SCHEMA: &'static str;
}

/// A plane's codec state for one connection.
///
/// One half per connection: the client half comes from opening the session, and one more half per
/// dialed upstream. It is bounded per half with a ceiling on halves per session. It may own a drop
/// implementation and foreign resources, it is cleared on upgrade, and it is poisoned and dropped
/// on a panic. This is the *only* place cross-frame codec state may live; a plane that keeps state
/// in its own fields is red under the interior-mutability scan.
pub struct PlaneSessionState {
    inner: Box<dyn Any + Send>,
}

impl PlaneSessionState {
    /// Wrap a plane's own state value.
    #[must_use]
    pub fn new<T: Any + Send>(state: T) -> Self {
        Self {
            inner: Box::new(state),
        }
    }

    /// Read the state back as the plane's own type.
    #[must_use]
    pub fn get<T: Any + Send>(&self) -> Option<&T> {
        self.inner.downcast_ref::<T>()
    }

    /// Read the state back mutably as the plane's own type.
    pub fn get_mut<T: Any + Send>(&mut self) -> Option<&mut T> {
        self.inner.downcast_mut::<T>()
    }
}

impl core::fmt::Debug for PlaneSessionState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PlaneSessionState(..)")
    }
}

/// The draft of a unit, before the kernel constructs it.
///
/// A draft carries what the plane read; the kernel writes the identity. The operation class here
/// is the one that prices the unit, which is why a differing class at the audit step is a dispute
/// rather than a re-price.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnitDraft<'u> {
    /// Which operation class this unit is.
    pub op: OpClassId,
    /// The decoded body and its resolved pointer spans.
    pub body_ir: Ir<'u>,
    /// Which earlier request this unit answers, where it answers one.
    pub correlates: Option<CorrelationRef<'u>>,
    /// The correlation an answer to this unit must carry.
    pub correlation_out: Option<CorrelationRef<'u>>,
    /// The facts the plane read off the bytes.
    pub facts: Facts<'u>,
}

/// One decoded response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Response<'u> {
    /// The decoded body and its resolved pointer spans.
    pub ir: Ir<'u>,
    /// How the plane says it ended.
    pub finish: FinishClass,
    /// The facts the plane read off it.
    pub facts: Facts<'u>,
}

/// What a plane makes of inbound bytes.
///
/// Every payload that carries a fact map is behind a pointer, and the answer itself is therefore
/// not `Copy`. A fact map is a fixed array of [`MAX_KEYS`](crate::bounded::MAX_KEYS) entries — over
/// a kilobyte — and this value is returned across the plane's dyn call once per arriving frame, so
/// embedding one by value meant memcpying a kilobyte per frame to carry a handful of keys. The
/// export path's content facts were already behind a pointer for exactly this reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ingress<'u> {
    /// Not yet a whole anything; hand me the next frame.
    NeedMore,
    /// A unit that stays open across frames.
    Open(Box<UnitDraft<'u>>),
    /// A unit that is complete in one frame.
    OneShot(Box<UnitDraft<'u>>),
    /// A challenge-response exchange.
    Handshake(Box<UnitDraft<'u>>),
    /// A frame belonging to an already-open unit, to be relayed under its hold.
    Frame {
        /// Which unit it belongs to.
        for_: Option<CorrelationRef<'u>>,
        /// The bytes to relay.
        relay: ScratchBytes<'u>,
        /// The facts the plane read off it.
        facts: Box<Facts<'u>>,
    },
    /// The end of an open unit.
    Close {
        /// Which unit ends.
        for_: Option<CorrelationRef<'u>>,
        /// The facts the plane read off the ending.
        facts: Box<Facts<'u>>,
    },
    /// Nothing; drop the frame, change no state.
    Discard {
        /// Why.
        reason: DiscardCode,
    },
}

/// What a plane makes of bytes coming back from an upstream.
///
/// Behind a pointer for the same reason [`Ingress`] is, and on the same path: one of these comes
/// back across the dyn call for every response frame of every open unit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Progress<'u> {
    /// Not yet a whole anything; hand me the next frame.
    NeedMore,
    /// An upstream pushed something that opens a unit of its own.
    Open(Box<UnitDraft<'u>>),
    /// An upstream pushed something complete in one frame.
    OneShot(Box<UnitDraft<'u>>),
    /// One response frame of an open unit.
    Frame {
        /// Which request it answers.
        for_: Option<CorrelationRef<'u>>,
        /// The decoded response.
        r: Box<Response<'u>>,
    },
    /// The last response frame.
    Terminal {
        /// Which request it answers.
        for_: Option<CorrelationRef<'u>>,
        /// The decoded response.
        r: Box<Response<'u>>,
    },
    /// Nothing; drop the frame, change no state.
    Discard {
        /// Why.
        reason: DiscardCode,
    },
}

/// What bytes mean.
///
/// Seven codec methods, seven fact methods and two introspection methods. Every one of them is
/// pure over its inputs, and none of them may perform input or output.
///
/// # Errors
/// Every codec method returns [`Decode`] or [`Encode`] when the bytes, or the unit, cannot be
/// expressed in this dialect's shape; the kernel then falls back to its own minimal rendering. A
/// decode error is not itself a refusal — a refusal is rendered through the refusal encoder.
pub trait Plane: Plugin + Send + Sync + 'static {
    /// Read inbound bytes.
    fn decode_ingress<'u>(
        &self,
        frames: &mut FrameCursor<'u>,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Ingress<'u>, Decode>;

    /// Write the outbound request for one verified destination.
    fn encode_egress<'u>(
        &self,
        u: &Unit<'u>,
        dest: &VerifiedDestination,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<EgressBody<'u>, Encode>;

    /// Write one inbound frame of an open unit onward to its destination. Returning nothing means
    /// the frame is consumed and nothing goes out for it.
    fn encode_ingress_frame<'u>(
        &self,
        u: &Unit<'u>,
        f: &Frame,
        dest: &VerifiedDestination,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Option<ScratchBytes<'u>>, Encode>;

    /// Read bytes coming back from an upstream.
    fn decode_response<'u>(
        &self,
        frames: &mut FrameCursor<'u>,
        dest: &VerifiedDestination,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Progress<'u>, Decode>;

    /// Write one response frame back to the client.
    fn encode_response<'u>(
        &self,
        r: &Response<'u>,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ScratchBytes<'u>, Encode>;

    /// Write a refusal in this dialect's shape. The codec state is borrowed immutably on purpose:
    /// a refusal must not advance codec state, or a sequence-numbered protocol that incremented
    /// its counter on one would desynchronise against a client that never saw the numbered message.
    fn encode_refusal<'u>(
        &self,
        refusal: &Refusal,
        draft: Option<&UnitDraft<'u>>,
        st: Option<&PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<ScratchBytes<'u>, Encode>;

    /// Write the end of a unit, where the dialect has one to write.
    fn encode_end<'u>(
        &self,
        u: &Unit<'u>,
        end: &UnitEnd,
        st: Option<&mut PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<Option<ScratchBytes<'u>>, Encode>;

    /// Say where the credential is, and narrow the claim's scheme if the dialect narrows it.
    ///
    /// A plane may only narrow within the alternatives its claim declares. Anything else is
    /// refused at the authenticate step; the plane never sees the credential either way.
    fn authenticate<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> crate::kinds::CredentialLocator;

    /// Say where this unit wants to go.
    fn verify<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> crate::dest::DestinationFacts;

    /// Say what resources this unit touches.
    fn approve<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> ScopeFacts;

    /// Say where the lane name, the response ceiling and the priced input span are.
    fn admit<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> AdmitFacts;

    /// Say which legs this unit needs.
    fn route<'u>(&self, u: &Unit<'u>, ctx: &Ctx<'u>) -> RoutePlan;

    /// Say where the metered quantities are in a response.
    fn meter<'u>(&self, u: &Unit<'u>, r: &Response<'u>, ctx: &Ctx<'u>) -> UsageLocators;

    /// Say what this unit was and how it ended.
    ///
    /// Called at the metering step's entry with the provisional ending. An operation class here
    /// that differs from the draft's is a dispute; the draft's class is what priced the unit.
    fn audit<'u>(&self, u: &Unit<'u>, out: &UnitEnd, ctx: &Ctx<'u>) -> AuditFacts;

    /// Answer one of this plane's declared read-only introspection verbs. Errors when the verb
    /// is not one this plane declares.
    ///
    /// The subject is the one bounded argument a projection may take: which registration, which
    /// agent, which server. A verb that projects over everything is asked with no subject; a verb
    /// that projects over one named thing is asked with its name. Without it a plane that answers
    /// per-name projections has no way to declare them — a key per registration is not open to it,
    /// because the verb key set is closed at registration — so it declares only the list verb and
    /// leaves the rest unanswerable.
    fn plane_facts<'u>(
        &self,
        verb: AdminVerbId,
        subject: Option<&'u str>,
        ctx: &Ctx<'u>,
    ) -> Result<crate::kinds::PlaneFacts<'u>, Decode>;

    /// Say what the response contained, for the record and the export path.
    fn content_facts<'u>(
        &self,
        u: &Unit<'u>,
        r: &Response<'u>,
        ctx: &Ctx<'u>,
    ) -> crate::kinds::ContentFacts<'u>;
}

/// A plane that can run over a session transport.
///
/// The registry requires this trait exactly when any transport the plane claims declares itself a
/// session transport. The two methods are where the plane's per-connection codec state comes from:
/// one half for the client connection, one per upstream the session dials.
pub trait SessionPlane: Plane {
    /// Open the client half of this session's codec state.
    fn open_session<'u>(&self, ctx: &Ctx<'u>) -> PlaneSessionState;

    /// Open one upstream half of this session's codec state.
    fn open_upstream<'u>(&self, dest: &VerifiedDestination, ctx: &Ctx<'u>) -> PlaneSessionState;
}

/// THE FACTS A PLANE STATES ABOUT ITSELF, as plain data — the item a plane crate exports to be
/// registered. Every field is a constant of the plane, read once at registration; nothing here is a
/// hook, a handle or a behaviour, so a plane crate states it naming nothing but this crate. The
/// behaviour a host runs for a plane is not a fact about the plane and is not here: the host keeps
/// that table itself, keyed by [`Self::key`], and folds this declaration into it.
///
/// Two planes sharing a grant kind is how one plane's grant admits another plane's traffic, and two
/// sharing a record kind is how one plane's records start answering another plane's question — so
/// these are the strings that must not agree by coincidence, and each is declared once, here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaneDeclaration {
    /// The registry key: the label a plane is installed, resolved and indexed by. Also the metrics
    /// label, the log label and the record resource prefix. Operator-visible.
    pub key: &'static str,
    /// TRUE for the one plane that declares itself the FALLBACK catch-all — the plane every unclaimed
    /// path falls through to, which mounts nothing and binds no audience. At most one plane in a
    /// process sets it; the fallback key is read off this flag, never spelled.
    pub fallback: bool,
    /// The top-level config section whose mere existence declares this plane, and the section the
    /// hook-reference grammar folds in for it.
    pub config_section: &'static str,
    /// The grant kinds that admit traffic ON this plane, in the plane's declared order. A slice
    /// because a plane may grant at more than one granularity.
    pub scope_kinds: &'static [&'static str],
    /// What ONE registration on this plane is called, in the words an operator reads back in a
    /// not-found answer.
    pub subject_noun: &'static str,
    /// The singular hyphenated noun for one registration in this plane's named-definition section —
    /// the spelling a recorded action (`<noun>.create`), a recorded resource (`<noun>:<name>`) and a
    /// validation subject are stamped with. A plane with no named-definition section never has it
    /// read, but still carries a sensible value.
    pub admin_noun: &'static str,
    /// The record resource kind for a registration on this plane, and the prefix of every action
    /// word the plane's verbs record.
    pub audit_kind: &'static str,
    /// The versioned domain this plane's card-signing subkey is derived under, or `None` for a plane
    /// that signs no cards. A constant, never a signer: the host derives and signs.
    pub card_signing_domain: Option<&'static str>,
    /// The `kid` prefix this plane stamps on its card signatures, or `None` for a plane that signs
    /// no cards.
    pub card_kid_prefix: Option<&'static str>,
    /// The top-level config sections this plane declares it owns the grammar of — distinct from
    /// [`Self::config_section`], which is the one section that declares the plane. A section is
    /// owned by exactly one plane; the host refuses a boot where two claim one.
    pub owned_config_sections: &'static [&'static str],
    /// The billable unit classes this plane ledgers, each with the unit family it counts in.
    /// Pairwise disjoint: no class is a subset of another. When the plane's section carries a rate
    /// card, the card must configure every class listed here. `&[]` for a plane that bills nothing.
    pub billable_classes: &'static [BillableClass],
    /// The fee units this plane counts — [`PER_REQUEST`] and/or [`PER_SESSION`]. A nonzero fee
    /// naming a unit not listed here is refused: a fee nothing counts charges nothing.
    pub fee_units: &'static [&'static str],
    /// The metric families this plane emits through the host's `counter_add` — the ONLY series it
    /// can add to over that seam. The host decodes labels for a declared family only, and admits a
    /// family in the reserved `busbar_` namespace only when it is one the host lets a plane carry
    /// (see [`check_metric_families`]). `&[]` for a plane that emits none.
    pub metric_families: &'static [MetricFamily],
}

/// One metric family a plane declares it emits: its series name, its kind and its label keys, in
/// the order the series renders them. Every sample the plane adds names the family and supplies
/// one value per key, positionally; the host renders exactly this name and these keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricFamily {
    /// The series name exactly as it renders (`^[a-z][a-z0-9_]{0,63}$`).
    pub name: &'static str,
    /// The family's kind — [`COUNTER`], the one kind a plane adds to.
    pub kind: &'static str,
    /// The label keys, in render order.
    pub label_keys: &'static [&'static str],
}

/// The counter kind: a family whose samples only ever add.
pub const COUNTER: &str = "counter";

/// The reserved first-party metric namespace. A plane's family in it is admitted only when the
/// host lists it (see [`check_metric_families`]).
pub const RESERVED_METRIC_PREFIX: &str = "busbar_";

/// The most label keys one family may declare — the cap the host's metric validator holds every
/// reported sample to.
pub const MAX_FAMILY_LABELS: usize = 8;

/// A series name or label key a scrape can carry: `^[a-z][a-z0-9_]{0,63}$`.
fn metric_ident(s: &str) -> bool {
    let mut bytes = s.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && s.len() <= 64
        && bytes.all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

/// THE METRIC-FAMILY GUARD over a set of declarations' [`PlaneDeclaration::metric_families`],
/// judged against the reserved series the HOST lets a plane carry (`carried`, supplied by the
/// caller as `(name, label keys)` rows — the host owns that list; a plane never supplies it).
/// `Ok(())` when every family is admissible, else the FIRST refusal:
///
/// * a name or label key outside `^[a-z][a-z0-9_]{0,63}$`, a repeated key, or more than
///   [`MAX_FAMILY_LABELS`] keys;
/// * a kind other than [`COUNTER`];
/// * a name in the reserved [`RESERVED_METRIC_PREFIX`] namespace that is not a `carried` row with
///   exactly these label keys in this order — a plane cannot mint a first-party series, and a
///   carried one renders byte-identically or not at all;
/// * a family two planes (or one plane twice) declare — one series, one writer.
///
/// Pure: declarations and the host's rows in, a verdict out. The host runs it over its boot fold;
/// a test drives it directly.
pub fn check_metric_families(
    decls: &[&PlaneDeclaration],
    carried: &[(&str, &[&str])],
) -> Result<(), String> {
    let mut seen: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
    for decl in decls {
        for f in decl.metric_families {
            let refuse = |why: String| Err(format!("plane `{}` declares {why}", decl.key));
            let keys = f.label_keys;
            let repeated = keys.iter().enumerate().any(|(i, k)| keys[..i].contains(k));
            if !metric_ident(f.name) || !keys.iter().all(|k| metric_ident(k)) || repeated {
                return refuse(format!(
                    "the metric family `{}` with label keys {keys:?}: a name and each key is \
                     `^[a-z][a-z0-9_]{{0,63}}$`, and no key repeats",
                    f.name
                ));
            }
            if keys.len() > MAX_FAMILY_LABELS || f.kind != COUNTER {
                return refuse(format!(
                    "the metric family `{}` of kind `{}` with {} label keys: a plane declares a \
                     `{COUNTER}` of at most {MAX_FAMILY_LABELS} keys",
                    f.name,
                    f.kind,
                    keys.len()
                ));
            }
            if f.name.starts_with(RESERVED_METRIC_PREFIX) && !carried.contains(&(f.name, keys)) {
                return refuse(format!(
                    "the metric family `{}` with label keys {keys:?}, in the reserved \
                     `{RESERVED_METRIC_PREFIX}` namespace: a plane carries only a first-party \
                     series the host lists, with exactly its label keys",
                    f.name
                ));
            }
            if let Some(other) = seen.insert(f.name, decl.key) {
                return refuse(format!(
                    "the metric family `{}`, which plane `{other}` declares too: one series has \
                     one writer",
                    f.name
                ));
            }
        }
    }
    Ok(())
}

/// One billable class a plane ledgers and the unit family its count is in — the family vocabulary
/// the plane's own meter-class declarations use (`token`, `duration`, `count`, `byte`, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BillableClass {
    /// The class string the plane's raw counts are keyed by.
    pub class: &'static str,
    /// The unit family the class counts in.
    pub family: &'static str,
}

/// The token family: every class a plane declares in it counts toward a `tokens:` cap.
pub const TOKEN_FAMILY: &str = "token";

/// The fee unit a plane counts once per billable request (`fees.per_request`).
pub const PER_REQUEST: &str = "per_request";

/// The fee unit a plane counts once per opened session (`fees.per_session`).
pub const PER_SESSION: &str = "per_session";

/// THE DUP-CLAIM GUARD over a set of declarations' [`PlaneDeclaration::owned_config_sections`],
/// judged against the sections the host still declares concretely (`reserved`, supplied by the
/// caller as plain section keys). `Ok(())` when every claim is disjoint and unique, else the FIRST
/// refusal: two planes claiming one section (one plane's grammar would answer for another's), or a
/// plane claiming a reserved section (the grammar would be declared twice).
///
/// Pure: a declaration list and a reserved-key list in, a verdict out. The host runs it over its
/// boot fold; a test drives it directly.
pub fn check_owned_config_claims(
    decls: &[&PlaneDeclaration],
    reserved: &[&'static str],
) -> Result<(), String> {
    // section key → the plane key that first claimed it, so a second claimant names its rival.
    let mut claimed: std::collections::BTreeMap<&'static str, &'static str> =
        std::collections::BTreeMap::new();
    for decl in decls {
        for &section in decl.owned_config_sections {
            if reserved.contains(&section) {
                return Err(format!(
                    "plane `{}` claims config section `{section}`, but core still owns it concretely: \
                     a section must be evicted from core's `DeployCfg` in the SAME change that a plane \
                     claims it, never before — else the grammar is declared twice and the config stops \
                     deserializing byte-identically",
                    decl.key
                ));
            }
            if let Some(other) = claimed.insert(section, decl.key) {
                return Err(format!(
                    "config section `{section}` is claimed by two planes (`{other}` and `{}`): a \
                     section is owned by exactly one plane, or one plane's grammar answers for \
                     another's",
                    decl.key
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/metric_family_tests.rs"]
mod metric_family_tests;
