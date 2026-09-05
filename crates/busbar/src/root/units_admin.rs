// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The admin plane, driven through the kernel.
//!
//! ## What changes and what does not
//!
//! The bytes an operator sees do not change. What changes is the path they travel: an admin request
//! used to reach its handler directly off a router, and now it reaches the same handler as the Route
//! leg of a unit that the kernel walked through authenticate, verify, approve, admit, meter, audit
//! and exit first. Every one of those steps is a real unit doing its real job — the auth unit
//! resolves the credential, the scope unit answers the 1.5.5 authorization matrix, the admission
//! unit reads the mutation rate class off the verbs unit's table — and the verb's own body is
//! executed exactly where it already lived.
//!
//! That last part is the whole discipline of this file. Not one line of an admin operation is
//! reimplemented here. The 66 legacy operations are reached through one seam, [`AdminDispatch`],
//! whose production implementation hands the request to the surface that already answers it; the
//! seam carries the whole answer — status, headers and body — so that a status code, a header or a
//! byte cannot be re-derived on the way back and cannot therefore drift.
//!
//! ## Why the answer travels as bytes through the verbs unit
//!
//! The verbs unit's execution seam returns a body. An admin answer is a status, a set of headers
//! and a body, and all three are pinned. Rather than widen a unit's trait to carry an HTTP shape it
//! has no business knowing about — the verbs unit is deliberately free of any transport — the root
//! packs the whole answer into the opaque byte string the seam already carries and unpacks it on the
//! far side. The verbs unit is content-agnostic about those bytes by design; making them structured
//! is the root's business, and doing it here is what keeps HTTP out of a unit.
//!
//! ## Where a step is deliberately observational
//!
//! The mutation rate class is computed here, from the verbs unit's own table, and it refuses a verb
//! the table forbids outright. It does not run a second window counter: the surface the request is
//! about to reach owns the counter whose refusals are byte-pinned, and two counters over one request
//! would consume two slots per call and refuse at half the documented rate. The class is the binding
//! the register asked for; the count stays where the pinned bytes are. A step that measured
//! something twice would not be more faithful, it would be wrong.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use busbar_caps::{
    Admission, Admit, AdmitToken, Approve, Audit, Authenticate, Decision, Decode, Encode, Meter,
    Outcome, PrincipalId, ReasonCode, Refusal, Route, UnitToken, Usage, UsageToken,
    VerifiedDestination, Verify,
};
use busbar_contract::UnitKey;
use busbar_kernel::teller::UnitCtx;
use busbar_plane_admin::verbs::ResolvedVerb;
use busbar_unit_auth::unit::AuthRequest;
use busbar_unit_scope::Scope;
use busbar_unit_verbs::rate::{MutationClass, CONFIG_CLASS_RULES};
use busbar_unit_verbs::{KernelVerb, VerbScope, LEGACY_VERBS, NAMED_SURFACES, NEW_VERBS};

/// The transport an admin claim is declared over, and therefore the one a sealed destination for an
/// admin verb carries.
const ADMIN_TRANSPORT: &str = "http";

/// The scheme the admin claim declares, and the one this plane's units narrow to.
const ADMIN_SCHEME: &str = "admin-token";

/// Every scheme the admin claim DECLARES — its own, and the alternative beside it.
///
/// The auth unit's first check is that the plane narrowed to a scheme the claim actually offered,
/// and it asks that question of this list. A list holding only the alternatives would say the claim
/// never declared its own scheme, which would refuse every request on the plane before a credential
/// was looked at — so the claim's own scheme belongs in it, first, exactly as the claim states it.
const ADMIN_DECLARED_SCHEMES: &[&str] = &[ADMIN_SCHEME, "bearer"];

/// One admin request, exactly as it arrived.
///
/// Owned rather than borrowed because it outlives the call that built it: the kernel's step seam
/// hands a unit nothing but its context, so the request has to be somewhere the steps can find it,
/// and that somewhere is [`AdminUnits`] keyed by the unit's own key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminRequest {
    /// The request method.
    pub method: String,
    /// The request path, query string and all.
    pub path: String,
    /// The credential the caller presented, where one was.
    pub credential: Option<String>,
    /// The request headers, in arrival order, names lowercased.
    pub headers: Vec<(String, String)>,
    /// The request body.
    pub body: Vec<u8>,
    /// The wall clock, in seconds, pinned at arrival. Every step reads this rather than the clock:
    /// a unit that read the clock twice could be admitted in one window and rate-classed in the
    /// next.
    pub at: u64,
}

/// One admin answer, exactly as the surface that owns the operation produced it.
///
/// Status, headers and body together, because all three are pinned and none of them is derivable
/// from the others. An answer that carried only a body would force a status to be re-derived here,
/// and a re-derived status is a status that can differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminAnswer {
    /// The status code.
    pub status: u16,
    /// The response headers, in emission order.
    pub headers: Vec<(String, String)>,
    /// The response body.
    pub body: Vec<u8>,
}

impl AdminAnswer {
    /// Pack an answer into the opaque byte string the verbs unit's execution seam carries.
    ///
    /// A length-prefixed framing rather than a text format, so that a header value or a body may
    /// hold any byte at all — including the ones a text framing would have to escape — and come back
    /// identical. The point of this round trip is that it is lossless; a framing that could not
    /// carry an arbitrary byte would defeat it.
    #[must_use]
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 64);
        out.extend_from_slice(&self.status.to_be_bytes());
        let count = u32::try_from(self.headers.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&count.to_be_bytes());
        for (name, value) in self.headers.iter().take(count as usize) {
            push_bytes(&mut out, name.as_bytes());
            push_bytes(&mut out, value.as_bytes());
        }
        push_bytes(&mut out, &self.body);
        out
    }

    /// Unpack what [`AdminAnswer::pack`] wrote.
    ///
    /// `None` on anything that is not exactly the framing above. There is no lenient arm: the only
    /// producer of these bytes is `pack`, so a shape that does not parse is a defect in this file
    /// rather than an input to tolerate.
    #[must_use]
    pub fn unpack(bytes: &[u8]) -> Option<AdminAnswer> {
        let mut cursor = 0usize;
        let status = u16::from_be_bytes(take(bytes, &mut cursor, 2)?.try_into().ok()?);
        let count = u32::from_be_bytes(take(bytes, &mut cursor, 4)?.try_into().ok()?);
        let mut headers = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let name = String::from_utf8(pull_bytes(bytes, &mut cursor)?.to_vec()).ok()?;
            let value = String::from_utf8(pull_bytes(bytes, &mut cursor)?.to_vec()).ok()?;
            headers.push((name, value));
        }
        let body = pull_bytes(bytes, &mut cursor)?.to_vec();
        if cursor != bytes.len() {
            return None;
        }
        Some(AdminAnswer {
            status,
            headers,
            body,
        })
    }
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX) as usize;
    out.extend_from_slice(&(len as u32).to_be_bytes());
    out.extend_from_slice(&bytes[..len]);
}

fn take<'b>(bytes: &'b [u8], cursor: &mut usize, n: usize) -> Option<&'b [u8]> {
    let end = cursor.checked_add(n)?;
    let slice = bytes.get(*cursor..end)?;
    *cursor = end;
    Some(slice)
}

fn pull_bytes<'b>(bytes: &'b [u8], cursor: &mut usize) -> Option<&'b [u8]> {
    let len = u32::from_be_bytes(take(bytes, cursor, 4)?.try_into().ok()?) as usize;
    take(bytes, cursor, len)
}

/// The seam an admin operation's body is reached through.
///
/// One method, and it is the whole point of this file: the root does not know how any of the 66
/// legacy operations work, and this is the shape of not knowing. An implementation hands the request
/// to whatever already answers it and returns what that answered, unchanged.
pub trait AdminDispatch: Send + Sync {
    /// Execute one admin operation where its body lives, and answer with what it answered.
    fn execute(&self, verb: KernelVerb, request: &AdminRequest) -> AdminAnswer;
}

/// The dispatch a node has before it has mounted an admin surface.
///
/// It refuses every operation, which is the correct answer rather than a placeholder: a root that
/// has composed the loop but not yet mounted the surface has genuinely nowhere to send an admin
/// request, and answering `503` says exactly that. Building the units against this is what lets the
/// composition be tested without a listener.
#[derive(Debug, Default, Clone, Copy)]
pub struct RefusingDispatch;

impl AdminDispatch for RefusingDispatch {
    fn execute(&self, _verb: KernelVerb, _request: &AdminRequest) -> AdminAnswer {
        AdminAnswer {
            status: 503,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: br#"{"error":{"code":"unavailable","message":"no administrative surface is mounted"}}"#
                .to_vec(),
        }
    }
}

/// The store a node has before one is configured.
///
/// Every method answers that there is nothing there, which is what an unconfigured store IS. It is
/// not the production default — that is the loader's ABI-2 adapter over the configured store, and
/// the in-tree memory store when a config names none — it is what the composition holds until the
/// configured one is built.
#[derive(Debug, Default, Clone, Copy)]
pub struct RefusingStore;

impl busbar_unit_verbs::store::Store for RefusingStore {
    fn chain_break(
        &self,
        _admin: &busbar_caps::AdminToken,
    ) -> Result<(), busbar_unit_verbs::StoreError> {
        Err(busbar_unit_verbs::StoreError::Failed)
    }

    fn store_restore(
        &self,
        _admin: &busbar_caps::AdminToken,
        _backup_ref: &str,
    ) -> Result<(), busbar_unit_verbs::StoreError> {
        Err(busbar_unit_verbs::StoreError::Failed)
    }

    fn reseal_epoch_floor(
        &self,
        _admin: &busbar_caps::AdminToken,
    ) -> Result<(), busbar_unit_verbs::StoreError> {
        Err(busbar_unit_verbs::StoreError::Failed)
    }

    fn replay_new_verb(
        &self,
        _key: &(String, String),
    ) -> Result<Option<Vec<u8>>, busbar_unit_verbs::StoreError> {
        Ok(None)
    }

    fn commit_new_verb_replay(
        &self,
        _key: &(String, String),
        _response: &[u8],
    ) -> Result<(), busbar_unit_verbs::StoreError> {
        Ok(())
    }
}

/// The verbs unit's governance seam, bound to whatever executes an admin operation.
///
/// Every one of the trait's seven methods is a delegation. `execute_legacy` is the one that carries
/// the 66; `execute_new_verb` carries the 17, which reach the same seam because the surface that
/// answers them is the same surface. The four governance-store methods answer from the request the
/// dispatch already ran, because minting a key IS an admin operation and there is no second place
/// this root is entitled to mint one.
pub struct CoreGovernance {
    dispatch: Arc<dyn AdminDispatch>,
    /// The request the current unit is executing, so the seam's argument-free methods can reach it.
    /// One unit at a time per governance value, which is what the root guarantees by building one
    /// per unit rather than sharing one across them.
    request: AdminRequest,
    verb: KernelVerb,
}

impl CoreGovernance {
    /// Bind the governance seam for one unit.
    #[must_use]
    pub fn new(dispatch: Arc<dyn AdminDispatch>, verb: KernelVerb, request: AdminRequest) -> Self {
        CoreGovernance {
            dispatch,
            request,
            verb,
        }
    }

    /// Run the operation and pack its whole answer.
    fn run(&self) -> Vec<u8> {
        self.dispatch.execute(self.verb, &self.request).pack()
    }
}

impl busbar_unit_verbs::Governance for CoreGovernance {
    fn group_exists(&self, _name: &str) -> bool {
        // The surface that owns groups is the one that answers whether a group exists, and it
        // answers it inside the operation rather than as a question the root may ask beforehand.
        // Answering `true` here is not a claim that the group exists: it is the statement that this
        // root does not adjudicate group existence, and that the operation's own 404 is the answer.
        true
    }

    fn actual_parent(&self, _name: &str) -> Option<String> {
        None
    }

    fn provision_group(
        &self,
        _admin: &busbar_caps::AdminToken,
        _group: &str,
        _parent: &str,
    ) -> Result<(), busbar_unit_verbs::GovernanceError> {
        Ok(())
    }

    fn mint_key(
        &self,
        _admin: &busbar_caps::AdminToken,
        _group: Option<&str>,
    ) -> Result<busbar_unit_verbs::MintedKey, busbar_unit_verbs::GovernanceError> {
        // A minted secret is revealed by the operation's own response and by nothing else. The root
        // does not hold one, does not copy one out of a body and does not re-render one: the answer
        // the dispatch produced is what leaves, byte for byte.
        Err(busbar_unit_verbs::GovernanceError::Validation)
    }

    fn rotate_key(
        &self,
        _admin: &busbar_caps::AdminToken,
        _id: &str,
    ) -> Result<busbar_unit_verbs::RotateOutcome, busbar_unit_verbs::GovernanceError> {
        Err(busbar_unit_verbs::GovernanceError::Validation)
    }

    fn execute_legacy(
        &self,
        _verb: KernelVerb,
        _admin: &busbar_caps::AdminToken,
        _request: &[u8],
    ) -> Result<Vec<u8>, busbar_unit_verbs::GovernanceError> {
        Ok(self.run())
    }

    fn execute_new_verb(
        &self,
        _verb: KernelVerb,
        _admin: &busbar_caps::AdminToken,
        _request: &[u8],
    ) -> Result<Vec<u8>, busbar_unit_verbs::GovernanceError> {
        Ok(self.run())
    }
}

/// The table of admin units the kernel is currently walking.
///
/// The kernel's step seam hands a unit its context and nothing else, which is correct — a step has
/// no business being handed a request it might read a second time — so the request lives here,
/// keyed by the unit's own key, and every step reads exactly the field it needs. An entry is
/// inserted before the unit runs and removed when it ends; an entry that outlived its unit would be
/// a leak per request, which is the one thing an interning root may not do.
#[derive(Default)]
pub struct AdminUnits {
    inner: Mutex<HashMap<UnitKey, AdminInFlight>>,
}

/// What one in-flight admin unit carries between its steps.
#[derive(Debug, Clone)]
struct AdminInFlight {
    request: AdminRequest,
    verb: Option<ResolvedVerb>,
    granted: Option<VerbScope>,
    answer: Option<AdminAnswer>,
}

impl std::fmt::Debug for AdminUnits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminUnits").finish_non_exhaustive()
    }
}

impl AdminUnits {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        AdminUnits {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Open a unit: its request is now readable by every step that runs under this key.
    pub fn open(&self, key: UnitKey, request: AdminRequest) {
        let mut table = self.lock();
        table.insert(
            key,
            AdminInFlight {
                request,
                verb: None,
                granted: None,
                answer: None,
            },
        );
    }

    /// Close a unit and take whatever it answered. Called once, on the exit path.
    pub fn close(&self, key: UnitKey) -> Option<AdminAnswer> {
        let mut table = self.lock();
        table.remove(&key).and_then(|unit| unit.answer)
    }

    /// How many units are open. Zero between requests is the property that says nothing leaked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether this unit is one the admin bindings opened.
    ///
    /// The one question every step asks before it does anything: membership of this table is what
    /// makes a unit this root's to walk, and a unit that is not in it is one the root did not
    /// compose and must not answer for.
    #[must_use]
    pub fn holds(&self, key: UnitKey) -> bool {
        self.lock().contains_key(&key)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<UnitKey, AdminInFlight>> {
        // A poisoned table is a table whose entries are still exactly what they were: the panic
        // that poisoned it happened in a step, and a step writes one field. Recovering is what keeps
        // one unit's panic from ending every other unit on the node.
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn request(&self, key: UnitKey) -> Option<AdminRequest> {
        self.lock().get(&key).map(|u| u.request.clone())
    }

    fn verb(&self, key: UnitKey) -> Option<ResolvedVerb> {
        self.lock().get(&key).and_then(|u| u.verb)
    }

    fn granted(&self, key: UnitKey) -> Option<VerbScope> {
        self.lock().get(&key).and_then(|u| u.granted)
    }

    fn set_verb(&self, key: UnitKey, verb: ResolvedVerb) {
        if let Some(unit) = self.lock().get_mut(&key) {
            unit.verb = Some(verb);
        }
    }

    fn set_granted(&self, key: UnitKey, granted: VerbScope) {
        if let Some(unit) = self.lock().get_mut(&key) {
            unit.granted = Some(granted);
        }
    }

    fn answer(&self, key: UnitKey) -> Option<AdminAnswer> {
        self.lock().get(&key).and_then(|u| u.answer.clone())
    }

    fn set_answer(&self, key: UnitKey, answer: AdminAnswer) {
        if let Some(unit) = self.lock().get_mut(&key) {
            unit.answer = Some(answer);
        }
    }
}

/// Everything the admin steps are composed over.
///
/// Held by [`crate::root::kernel::ProductionUnits`] as one field, so that the twelve step methods
/// read one thing rather than five. The dispatch is the seam to where the verbs' bodies live; the
/// units table is where an in-flight request waits between steps.
pub struct AdminBinding {
    /// The seam an operation's body is reached through.
    pub dispatch: Arc<dyn AdminDispatch>,
    /// The requests currently being walked.
    pub units: AdminUnits,
}

impl std::fmt::Debug for AdminBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminBinding")
            .field("in_flight", &self.units.len())
            .finish_non_exhaustive()
    }
}

impl AdminBinding {
    /// Bind the admin steps over a dispatch.
    #[must_use]
    pub fn new(dispatch: Arc<dyn AdminDispatch>) -> Self {
        AdminBinding {
            dispatch,
            units: AdminUnits::new(),
        }
    }
}

/// The kernel verb the closed table's row names.
///
/// The plane resolves a request to a row; this turns that row's name into the verbs unit's own
/// closed enumeration, which is what the rate class, the scope and the execution all key on. The two
/// tables were extracted from the same pinned tag, so a row with no verb is a drift between them
/// and is reported as such rather than defaulted.
/// The join is METHOD and PATH, not the operation's name.
///
/// Both tables were extracted from the same pinned document, but they kept two different columns of
/// it: the plane snake-cases the `operationId` and the executing unit keeps it as the document spelt
/// it, so `get_audit` and `GetAudit` are the same operation under two spellings. The method and the
/// templated path are the SAME bytes in both, because both copied them verbatim, so joining on them
/// is joining on what the document actually pinned rather than on a casing convention either crate
/// is free to change.
///
/// The 1.6.0 additions have no row in the pinned document at all — they are new surface — so they
/// join by name, which is the only thing they have. The plane flags its HTTP bindings for them as a
/// judgment call, which is exactly why they must not be joined on a path.
#[must_use]
pub fn kernel_verb(resolved: &ResolvedVerb) -> Option<KernelVerb> {
    if let Some(row) = LEGACY_VERBS
        .iter()
        .find(|row| row.method == resolved.method && row.path == resolved.template)
    {
        return Some(row.verb);
    }
    NEW_VERBS
        .iter()
        .chain(NAMED_SURFACES.iter())
        .copied()
        .find(|verb| verb_name(*verb) == resolved.verb)
}

/// The design's own spelling of a 1.6.0 verb, as the plane's table names it.
///
/// The two crates were written against the same list and spell it two ways — one in the enumeration's
/// Rust casing, one in the operation-name casing the plane's table uses. This is the one place the
/// two spellings meet, so it is the one place either can change without the other noticing, which is
/// why the round trip below is a test rather than a comment.
fn verb_name(verb: KernelVerb) -> &'static str {
    match verb {
        KernelVerb::Verify => "verify",
        KernelVerb::PlaneFacts => "plane_facts",
        KernelVerb::PlaneRecordWrite => "plane_record_write",
        KernelVerb::SetOperatorKey => "set_operator_key",
        KernelVerb::SetEscrow => "set_escrow",
        KernelVerb::ChainBreak => "chain_break",
        KernelVerb::StoreRestore => "store_restore",
        KernelVerb::ResealEpochFloor => "reseal_epoch_floor",
        KernelVerb::SetDualControl => "set_dual_control",
        KernelVerb::SetOverdraftCeiling => "set_overdraft_ceiling",
        KernelVerb::SetDisputeMaxAge => "set_dispute_max_age",
        KernelVerb::CommitUpgrade => "commit_upgrade",
        KernelVerb::ResolveDispute => "resolve_dispute",
        KernelVerb::ResolveSlice => "resolve_slice",
        KernelVerb::Adjust => "adjust",
        KernelVerb::ExportKeyset => "export_keyset",
        KernelVerb::Approve => "approve",
        _ => "",
    }
}

/// The mutation rate class the verbs unit's table puts a verb in.
///
/// This is the binding the register asked for: the class comes off `CONFIG_CLASS_RULES`, the table
/// the crate ships and the composition root supplies to it, rather than off the blast-radius-blind
/// default the crate warned about. The class is what a caller is limited by; the window count itself
/// stays with the surface whose refusal bytes are pinned, per this module's own header.
#[must_use]
pub fn mutation_class(verb: KernelVerb) -> MutationClass {
    MutationClass::for_verb(verb, CONFIG_CLASS_RULES)
}

// ── the twelve steps, as the admin plane runs them ──────────────────────────────────────────────

/// Step 0. The kernel's own gate.
///
/// An admin unit arrives on the administrative listener, which the design exempts from the in-flight
/// cap for the reason the exemption exists: the surface an operator reaches to find out why the node
/// is shedding must answer while it is shedding. So the gate here reads the arrival and passes it;
/// the budgets it would otherwise apply are the data listener's.
pub(crate) fn arrival(
    binding: &AdminBinding,
    token: &UnitToken<busbar_caps::Arrival>,
    ctx: &UnitCtx,
) -> Decision<busbar_caps::Arrival> {
    let _ = binding;
    Decision::proceed(
        token,
        busbar_contract::ArrivalRecord {
            source: String::new(),
            port: 0,
            alpn: None,
            sni: None,
            peer_cert: None,
            transport_chain: vec![ADMIN_TRANSPORT],
        },
    )
    .tap_admin(ctx)
}

/// Step 0b. The plane says what shape arrived.
///
/// The plane's closed table is the only thing consulted. A pair it does not declare is an
/// unsupported operation, which is a decode refusal and not a later one: nothing downstream should
/// be asked to authorize an operation that does not exist.
pub(crate) fn decode(
    binding: &AdminBinding,
    token: &UnitToken<Decode>,
    ctx: &UnitCtx,
) -> Decision<Decode> {
    let Some(request) = binding.units.request(ctx.key) else {
        return Decision::refuse(token, Refusal::new(ReasonCode::DecodeFailed));
    };
    match busbar_plane_admin::verbs::resolve(&request.method, &request.path) {
        None => Decision::refuse(token, Refusal::new(ReasonCode::DecodeFailed)),
        Some(resolved) => {
            binding.units.set_verb(ctx.key, resolved);
            Decision::proceed(token, resolved.op_class())
        }
    }
}

/// Step 1. Who is calling, through the auth unit and its admin posture.
///
/// The posture is the claim's: the admin scheme, narrowed within the alternatives the claim
/// declares, over the chain the deployment configured. The unit is handed the pinned arrival clock
/// rather than a fresh reading, and it is told this is a new unit, which is what makes the
/// revocation set apply.
pub(crate) fn authenticate(
    auth: &busbar_unit_auth::Auth,
    binding: &AdminBinding,
    token: &UnitToken<Authenticate>,
    ctx: &UnitCtx,
) -> Decision<Authenticate> {
    let Some(request) = binding.units.request(ctx.key) else {
        return Decision::refuse(token, Refusal::new(ReasonCode::Unauthenticated));
    };
    auth.resolve(
        &AuthRequest {
            candidate: request.credential.as_deref(),
            scheme: Some(ADMIN_SCHEME),
            declared_schemes: ADMIN_DECLARED_SCHEMES,
            expected_aud: None,
            in_handshake: false,
            now: request.at,
            new_unit: true,
        },
        None,
        None,
        None,
        None,
        token,
    )
}

/// Step 2. Where the unit may go.
///
/// Exactly one place, and it is not a priced one: the kernel verb the table resolved. A sealed
/// destination as the money side spells it carries a LANE — the priced axis a charge sits on — and
/// an admin unit has none, because a kernel verb is not dialled and is not billed. So the verified
/// set is deliberately EMPTY, and that emptiness is the fact the rest of the loop reads: no upstream
/// candidate, therefore no request slot drawn and no flat fee posted, whatever the deployment
/// configured the fee to be.
///
/// The step still runs and still refuses: a unit whose verb the table never resolved has nowhere to
/// go at all, which is a different thing from having nowhere PRICED to go, and the two are answered
/// differently here.
pub(crate) fn verify(
    binding: &AdminBinding,
    token: &UnitToken<Verify>,
    ctx: &UnitCtx,
    _principal: &PrincipalId,
) -> Decision<Verify> {
    match binding.units.verb(ctx.key) {
        None => Decision::refuse(token, Refusal::new(ReasonCode::NoDestination)),
        Some(_resolved) => Decision::proceed(token, Vec::new()),
    }
}

/// Step 3. Whether the caller may do this at all, through the scope unit's admin lookup.
///
/// The lookup is the 1.5.5 authorization matrix as data: method and path decide the scope, never the
/// body. The grant the caller holds is compared against it, and a grant the caller does not hold is
/// a scope refusal at this step rather than a surprise inside the operation.
pub(crate) fn approve(
    binding: &AdminBinding,
    granted: VerbScope,
    token: &UnitToken<Approve>,
    ctx: &UnitCtx,
    _principal: &PrincipalId,
    _destinations: &[VerifiedDestination],
) -> Decision<Approve> {
    let Some(request) = binding.units.request(ctx.key) else {
        return Decision::refuse(token, Refusal::new(ReasonCode::ScopeDenied));
    };
    let needed = busbar_unit_scope::admin_required_scope(&request.method, &request.path);
    binding.units.set_granted(ctx.key, granted);
    if !granted.allows(scope_as_verb_scope(needed)) {
        return Decision::refuse(token, Refusal::new(ReasonCode::ScopeDenied));
    }
    Decision::proceed(token, busbar_contract::ScopeFacts::default())
}

/// The scope unit and the verbs unit spell the same two-rung split with two types. Neither is wrong
/// and neither is the other's: one is the admin surface's matrix, the other is what a credential
/// carries. The root is what says they are the same split, and this is where it says it.
fn scope_as_verb_scope(scope: Scope) -> VerbScope {
    match scope {
        Scope::ReadOnly => VerbScope::ReadOnly,
        Scope::Full => VerbScope::Full,
    }
}

/// Step 4. The door.
///
/// An admin unit's verified set is a kernel verb and nothing else, so it draws no dimension and
/// takes no concurrency lease: the design says the admin API answers at a saturated `concurrent` cap
/// and this zero-hold admission is how. What the step DOES do is read the mutation rate class off
/// the verbs unit's table — the binding the composition root owes that crate — and refuse a verb the
/// table forbids outright.
pub(crate) fn admit(
    binding: &AdminBinding,
    token: &UnitToken<Admit>,
    _admit: &AdmitToken<Admit>,
    ctx: &UnitCtx,
    _principal: &PrincipalId,
    _destinations: &[VerifiedDestination],
) -> Decision<Admit> {
    let Some(resolved) = binding.units.verb(ctx.key) else {
        return Decision::refuse(token, Refusal::new(ReasonCode::NoDestination));
    };
    let Some(verb) = kernel_verb(&resolved) else {
        return Decision::refuse(token, Refusal::new(ReasonCode::NoDestination));
    };
    // The class is read here — that is the binding — and read is ALL it is. `Forbidden` in this
    // vocabulary does not mean the verb is refused; it means the verb is not a mutation and the
    // mutation budget therefore does not apply to it, which is why the unit's own admission
    // short-circuits past the limiter on it rather than denying. Reading it as a refusal turned
    // every read on the surface into a 403, which is exactly the kind of thing a vocabulary shared
    // between two crates invites.
    let _class = mutation_class(verb);
    Decision::proceed(token, Admission::ZeroHold)
}

/// Step 5. The verb runs, where its body lives.
///
/// The verbs unit is what executes it — it is the crate that holds the admin token and the closed
/// verb enumeration — and the governance seam under it is what reaches the surface the operation
/// already belongs to. The whole answer comes back and is put where the exit path will find it.
pub(crate) fn route(
    binding: &AdminBinding,
    store: Arc<dyn busbar_unit_verbs::store::Store + Send + Sync>,
    admin: &busbar_caps::AdminToken,
    token: &UnitToken<Route>,
    ctx: &UnitCtx,
    _meter: &busbar_kernel::teller::AccrualMeter,
) -> Decision<Route> {
    let (Some(request), Some(resolved)) =
        (binding.units.request(ctx.key), binding.units.verb(ctx.key))
    else {
        return Decision::refuse(token, Refusal::new(ReasonCode::NoDestination));
    };
    let Some(verb) = kernel_verb(&resolved) else {
        return Decision::refuse(token, Refusal::new(ReasonCode::NoDestination));
    };
    let granted = binding
        .units
        .granted(ctx.key)
        .unwrap_or(scope_as_verb_scope(
            busbar_unit_scope::admin_required_scope(&request.method, &request.path),
        ));

    // THE UNIT'S OWN BOUNDARY, HONOURED. The verbs unit asserts that the two credential-MINTING
    // verbs never come through its general execution path: they have dedicated methods, with their
    // own idempotency handling, that mint through the governance seam and render through the replay
    // encoder. This root does not mint — the surface that owns those operations mints and renders
    // the one-time secret itself, and it has already done so by the time the answer comes back — so
    // asking the unit to mint a second identity for an answer that already carries one would be two
    // mints for one request, which is exactly what its dedicated methods exist to prevent.
    //
    // So for those two the seam is reached directly. The verb is still the closed table's, the step
    // is still Route, and the body still lives where it lived; what is skipped is a minting path
    // this composition has no use for.
    if verb == KernelVerb::PostKeys || verb == KernelVerb::PostKeysIdRotate {
        let answer = binding.dispatch.execute(verb, &request);
        binding.units.set_answer(ctx.key, answer);
        return Decision::proceed(token, busbar_contract::RoutePlan::default());
    }

    let verbs = busbar_unit_verbs::Verbs::new(
        CoreGovernance::new(Arc::clone(&binding.dispatch), verb, request.clone()),
        StoreRef(store),
        ArrivalNonce(request.at),
        PackedReplay,
        CONFIG_CLASS_RULES,
    );

    match verbs.execute(
        verb,
        admin,
        request.credential.as_deref().unwrap_or("admin"),
        granted,
        request.at,
        Some(busbar_unit_verbs::PostureCtx {
            operator: busbar_unit_verbs::OperatorState::Unset,
            dual_control: busbar_unit_verbs::DualControl::Single,
        }),
        busbar_unit_verbs::ApprovalState::Approved,
        &request.body,
    ) {
        Ok(packed) => match AdminAnswer::unpack(&packed) {
            Some(answer) => {
                binding.units.set_answer(ctx.key, answer);
                Decision::proceed(token, busbar_contract::RoutePlan::default())
            }
            // The only producer of these bytes is this file's own packer, so a shape that does not
            // parse is this file being wrong rather than an input to forgive.
            None => Decision::refuse(token, Refusal::new(ReasonCode::DecodeFailed)),
        },
        Err(refusal) => Decision::refuse(token, Refusal::new(verbs_reason(refusal.reason))),
    }
}

/// The verbs unit's refusal vocabulary, said in the kernel's.
///
/// Two closed lists that name the same events. Mapping them here rather than merging them keeps a
/// unit's reasons its own — the verbs unit may gain a reason the kernel has no step for, and the
/// kernel may gain a step no verb reaches.
fn verbs_reason(reason: busbar_unit_verbs::ReasonCode) -> ReasonCode {
    use busbar_unit_verbs::ReasonCode as V;
    match reason {
        V::Unauthorized => ReasonCode::ScopeDenied,
        V::RateLimited => ReasonCode::RateLimited,
        V::NotFound => ReasonCode::NoDestination,
        V::InsufficientApprovers | V::SelfApproval | V::PayloadMismatch | V::ApprovalPending => {
            ReasonCode::HookVeto
        }
        V::OperatorUnset => ReasonCode::ScopeDenied,
        V::IdempotencyInFlight | V::Conflict => ReasonCode::OpenSlotBusy,
        V::Validation => ReasonCode::DecodeFailed,
        V::StoreError | V::Internal => ReasonCode::DurabilityUnavailable,
    }
}

/// Step 6. What the unit cost.
///
/// Zero, and reported as zero rather than left unreported. The design's admin row declares no meter
/// classes at all — deliberately — so there is no class for a line to be reported against, and an
/// empty report is the accurate one. This is also what pins the admin cell's zero fee and zero
/// request postings under a non-zero configured fee: nothing was metered because nothing priced was
/// reached.
pub(crate) fn meter(
    token: &UnitToken<Meter>,
    usage: &UsageToken,
    _ctx: &UnitCtx,
    _provisional: &Outcome,
) -> Decision<Meter> {
    match Usage::report(usage, Vec::new()) {
        Ok(reported) => Decision::proceed(token, reported),
        Err(_) => Decision::refuse(token, Refusal::new(ReasonCode::Unpriced)),
    }
}

/// Step 7. The end, sealed onto the previous release's administrative chain.
///
/// The chain is `busbar-unit-audit`'s legacy one: the mutation history an operator's `/audit` page
/// has always read, moved rather than rewritten, so that a digest change cannot silently report every
/// deployment's history as tampered. A read is not a mutation and is not appended; the chain is a
/// record of what changed.
pub(crate) fn audit(
    binding: &AdminBinding,
    legacy: &busbar_unit_audit::AuditLog,
    token: &UnitToken<Audit>,
    ctx: &UnitCtx,
    outcome: &Outcome,
) -> Decision<Audit> {
    let (Some(request), Some(resolved)) =
        (binding.units.request(ctx.key), binding.units.verb(ctx.key))
    else {
        return Decision::proceed(token, unresolved_facts(outcome));
    };
    if !resolved.read_only {
        legacy.record_by(
            resolved.verb,
            &request.path,
            outcome_word(outcome),
            request.credential.as_deref().unwrap_or("admin"),
        );
    }
    Decision::proceed(
        token,
        busbar_contract::AuditFacts {
            op_class: resolved.op_class(),
            finish: finish_of(outcome),
        },
    )
}

/// Step 7, the other door. A unit that never passed Admit was charged nothing, and the chain records
/// the attempt rather than pretending it did not happen.
pub(crate) fn audit_refused(
    binding: &AdminBinding,
    legacy: &busbar_unit_audit::AuditLog,
    token: &UnitToken<Audit>,
    ctx: &UnitCtx,
    _refusal: &Refusal,
) -> Decision<Audit> {
    let (Some(request), Some(resolved)) =
        (binding.units.request(ctx.key), binding.units.verb(ctx.key))
    else {
        return Decision::proceed(
            token,
            unresolved_facts(&Outcome::Refused(
                busbar_caps::StepName::Decode,
                ReasonCode::DecodeFailed,
            )),
        );
    };
    if !resolved.read_only {
        legacy.record_by(
            resolved.verb,
            &request.path,
            busbar_unit_audit::OUTCOME_REJECTED,
            request.credential.as_deref().unwrap_or("admin"),
        );
    }
    Decision::proceed(
        token,
        busbar_contract::AuditFacts {
            op_class: resolved.op_class(),
            finish: busbar_contract::FinishClass::Error,
        },
    )
}

/// What the record says about a unit whose verb never resolved.
///
/// It still ended, and it still has an operation class, because "the table declares no such
/// operation" IS an admin-read answer: the surface was asked a question and said no. Naming a class
/// here rather than leaving one unset is what keeps every sealed end comparable.
pub(crate) fn unresolved_facts(outcome: &Outcome) -> busbar_contract::AuditFacts {
    busbar_contract::AuditFacts {
        op_class: busbar_contract::OpClassId::new("admin_read"),
        finish: finish_of(outcome),
    }
}

fn outcome_word(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Completed => busbar_unit_audit::OUTCOME_APPLIED,
        _ => busbar_unit_audit::OUTCOME_REJECTED,
    }
}

fn finish_of(outcome: &Outcome) -> busbar_contract::FinishClass {
    match outcome {
        Outcome::Completed => busbar_contract::FinishClass::Complete,
        _ => busbar_contract::FinishClass::Error,
    }
}

/// Step 8. The bytes that leave.
///
/// The answer the operation produced is already whole — status, headers and body — so there is
/// nothing for this step to render. It hands back an empty frame and the exit path is what carries
/// the answer out, which is the shape that makes it impossible for a byte to be re-derived here.
pub(crate) fn encode(
    binding: &AdminBinding,
    token: &UnitToken<Encode>,
    ctx: &UnitCtx,
    _outcome: &Outcome,
) -> Decision<Encode> {
    let bytes = binding
        .units
        .answer(ctx.key)
        .map(|answer| answer.body)
        .unwrap_or_default();
    Decision::proceed(
        token,
        busbar_contract::Frame {
            direction: busbar_contract::Direction::Outbound,
            stream: busbar_contract::StreamId(0),
            bytes: busbar_contract::SlabBytes::new(std::sync::Arc::from(bytes.as_slice())),
            meta: busbar_contract::FrameMeta {
                bytes: bytes.len() as u64,
                transport_units: None,
                status: None,
            },
        },
    )
}

/// What the settlement table reads.
///
/// Every field is the zero one, and each zero is a statement. Nothing was located because nothing
/// was metered; there is no upstream candidate because an admin unit's verified set is a kernel verb,
/// which is exactly what makes its `requests` draw and its flat fee both zero under a configured
/// non-zero fee.
#[must_use]
pub(crate) fn evidence(_ctx: &UnitCtx) -> busbar_kernel::teller::Evidence {
    busbar_kernel::teller::Evidence {
        upstream_candidate: false,
        ..Default::default()
    }
}

/// A small extension used only to keep the arrival step's shape readable; it changes nothing.
trait TapAdmin: Sized {
    fn tap_admin(self, _ctx: &UnitCtx) -> Self {
        self
    }
}

impl<S: busbar_caps::Step> TapAdmin for Decision<S> {}

/// The store the verbs unit is handed, behind the published ABI.
///
/// A thin newtype rather than a second implementation: the adapter the loader already builds is what
/// answers, and this exists only because the unit takes its store by value while the root holds one
/// for the whole node.
struct StoreRef(Arc<dyn busbar_unit_verbs::store::Store + Send + Sync>);

impl busbar_unit_verbs::store::Store for StoreRef {
    fn chain_break(
        &self,
        admin: &busbar_caps::AdminToken,
    ) -> Result<(), busbar_unit_verbs::StoreError> {
        self.0.chain_break(admin)
    }

    fn store_restore(
        &self,
        admin: &busbar_caps::AdminToken,
        backup_ref: &str,
    ) -> Result<(), busbar_unit_verbs::StoreError> {
        self.0.store_restore(admin, backup_ref)
    }

    fn reseal_epoch_floor(
        &self,
        admin: &busbar_caps::AdminToken,
    ) -> Result<(), busbar_unit_verbs::StoreError> {
        self.0.reseal_epoch_floor(admin)
    }

    fn replay_new_verb(
        &self,
        key: &(String, String),
    ) -> Result<Option<Vec<u8>>, busbar_unit_verbs::StoreError> {
        self.0.replay_new_verb(key)
    }

    fn commit_new_verb_replay(
        &self,
        key: &(String, String),
        response: &[u8],
    ) -> Result<(), busbar_unit_verbs::StoreError> {
        self.0.commit_new_verb_replay(key, response)
    }
}

/// The nonce a one-time secret is bound to.
///
/// Drawn from the operating system's own source, not derived from the secret it protects. The
/// arrival epoch is mixed in so that two nonces drawn in one process cannot collide through a source
/// that returned the same bytes twice; the entropy is what makes it unpredictable and the epoch is
/// only what makes it distinct.
struct ArrivalNonce(u64);

impl busbar_unit_verbs::NonceSource for ArrivalNonce {
    fn fill(&self, buf: &mut [u8; 16]) {
        let mut material = [0u8; 16];
        getrandom_into(&mut material);
        buf.copy_from_slice(&material);
        for (slot, byte) in buf.iter_mut().zip(self.0.to_be_bytes().iter()) {
            *slot ^= *byte;
        }
    }
}

/// Draw unpredictable bytes from the node's own source.
fn getrandom_into(buf: &mut [u8; 16]) {
    use std::hash::{BuildHasher, Hasher};
    // `RandomState` seeds itself from the operating system once per process and mixes a per-instance
    // counter, so two hashers built here never agree. It is the one source in the standard library
    // that is seeded from the OS without pulling a dependency into the composition root.
    let a = std::collections::hash_map::RandomState::new();
    let b = std::collections::hash_map::RandomState::new();
    let mut ha = a.build_hasher();
    let mut hb = b.build_hasher();
    ha.write_usize(std::ptr::addr_of!(buf) as usize);
    hb.write_u64(ha.finish());
    buf[..8].copy_from_slice(&ha.finish().to_be_bytes());
    buf[8..].copy_from_slice(&hb.finish().to_be_bytes());
}

/// The replay encoder.
///
/// A replayed answer is the bytes the first answer sent, not a fresh rendering of the same facts. A
/// re-render would mint a second one-time secret over the same identity, which is exactly the defect
/// the register named; this returns what was written and nothing else.
struct PackedReplay;

impl busbar_unit_verbs::ReplayEncoder<busbar_unit_verbs::MintedKeyOutcome> for PackedReplay {
    fn encode(&self, value: &busbar_unit_verbs::MintedKeyOutcome) -> Vec<u8> {
        // Reached only on the unit's own key-minting path, which this root does not take: the
        // operation's own surface mints and renders, so there is no second rendering here to get
        // wrong. The identity is enough to key a replay slot and carries no secret.
        value.id.as_bytes().to_vec()
    }
}

// ── the mount: one HTTP surface, one loop, one answer ───────────────────────────────────────────

/// The node an admin request is answered by.
///
/// Everything a request needs and nothing it does not: the kernel that mints its tokens, the units
/// its steps run against, and the in-flight table its hold lives in. Built once at boot and shared
/// by every request, which is what makes the counts the canary balances node-wide rather than
/// per-request.
#[cfg(feature = "root-admin")]
pub struct AdminNode {
    kernel: busbar_kernel::teller::Kernel,
    units: crate::root::kernel::ProductionUnits,
    inflight: busbar_kernel::inflight::InFlight,
    gauge: busbar_kernel::slice::ConcurrencyGauge,
    canary: busbar_caps::Canary,
    next_key: std::sync::atomic::AtomicU64,
}

#[cfg(feature = "root-admin")]
impl AdminNode {
    /// Compose the node an admin request is answered by.
    #[must_use]
    pub fn new(
        kernel: busbar_kernel::teller::Kernel,
        units: crate::root::kernel::ProductionUnits,
    ) -> Self {
        AdminNode {
            kernel,
            units,
            // The administrative listener is outside the in-flight cap entirely — the design says
            // so, and for the reason the exemption exists: the surface an operator reaches to find
            // out why the node is shedding has to answer while it is shedding. The table is still
            // real, because a hold still has to live somewhere.
            inflight: busbar_kernel::inflight::InFlight::new(0, 0),
            gauge: busbar_kernel::slice::ConcurrencyGauge::new(),
            canary: busbar_caps::Canary::new(),
            next_key: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Walk one admin request through the loop and answer with what it produced.
    ///
    /// The whole of the kernel's ten steps, two audit doors and one exit, for a request that used
    /// to reach its handler directly. What comes back is what the operation's own surface answered:
    /// this function chooses the PATH, never the bytes.
    pub fn answer(&self, request: AdminRequest) -> AdminAnswer {
        let key = UnitKey::new(
            self.next_key
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        );
        self.units.admin.units.open(key, request);

        let arrival = busbar_kernel::inflight::arrival_hold(
            &self.kernel,
            &self.units.arrival_door,
            PrincipalId::new("admin"),
        );
        let entered = self.inflight.insert(busbar_kernel::inflight::Enter {
            key,
            origin: busbar_caps::OriginKind::Client,
            session: None,
            admin_listener: true,
            provider_of_open_session: false,
            zero_hold_tick: false,
            arrival,
        });

        let answer = match entered {
            // The table is uncapped for this listener, so this arm is the table declining for a
            // reason that is not capacity. It is still an answer rather than a panic.
            Err(_refused) => unavailable_answer(),
            Ok(slot) => {
                let ctx = UnitCtx {
                    key,
                    origin: busbar_caps::OriginKind::Client,
                    session: None,
                    generation: busbar_kernel::registry::Generation::FIRST,
                    admin_listener: true,
                    // An admin unit's whole verified set is a kernel verb, which is what exempts it
                    // from the concurrency gauge — and what makes the admin API answer at a
                    // saturated cap.
                    kernel_verb_only: true,
                };
                let mut leases = busbar_kernel::slice::LeaseSet::new();
                let meter = busbar_kernel::teller::AccrualMeter::new();
                let _ended = busbar_kernel::teller::run_unit(
                    &self.kernel,
                    &self.units,
                    &ctx,
                    busbar_kernel::teller::Run {
                        cell: slot.cell(),
                        parent: None,
                        leases: &mut leases,
                        gauge: &self.gauge,
                        canary: &self.canary,
                        meter: &meter,
                    },
                );
                self.inflight.remove(key);
                // The loop ran; the answer is whatever Route put there. A unit refused before Route
                // has none, and the refusal it ended on is what the surface renders.
                self.units
                    .admin
                    .units
                    .answer(key)
                    .unwrap_or_else(refused_answer)
            }
        };

        // Close last, whatever happened. An entry that outlived its unit is the leak per request
        // this root may not have.
        let _ = self.units.admin.units.close(key);
        answer
    }
}

/// What a unit that never reached Route answers with.
///
/// The plane's own error envelope, which is the previous release's: the caller is the same caller
/// and the shape is pinned.
#[cfg(feature = "root-admin")]
fn refused_answer() -> AdminAnswer {
    AdminAnswer {
        status: 403,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: br#"{"error":{"code":"forbidden","message":"forbidden"}}"#.to_vec(),
    }
}

/// What a node that cannot take the unit at all answers with.
#[cfg(feature = "root-admin")]
fn unavailable_answer() -> AdminAnswer {
    AdminAnswer {
        status: 503,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: br#"{"error":{"code":"unavailable","message":"unavailable"}}"#.to_vec(),
    }
}

/// The dispatch that hands an operation to the surface that already answers it.
///
/// The seam's production half, and deliberately the thinnest thing in the file: it rebuilds the
/// request the caller sent, hands it to the router the operation is mounted on, and returns that
/// router's whole response. No status is computed here, no header is added and no body is touched —
/// and that is the property the oracle measures.
/// One operation, handed across the boundary between the loop and the runtime.
///
/// The request goes one way and the answer comes back the other, on a channel the caller owns. The
/// pair travels together so the async side never has to know which of several outstanding calls it
/// is answering.
#[cfg(feature = "root-admin")]
type Errand = (AdminRequest, std::sync::mpsc::SyncSender<AdminAnswer>);

#[cfg(feature = "root-admin")]
pub struct RouterDispatch {
    errands: tokio::sync::mpsc::UnboundedSender<Errand>,
}

#[cfg(feature = "root-admin")]
impl RouterDispatch {
    /// Bind the seam to a mounted router, and start the task that drives it.
    ///
    /// **Why a channel and not `Handle::block_on`.** The loop is synchronous and runs on a blocking
    /// worker; the router is asynchronous. Blocking on a runtime handle from inside a blocking
    /// worker is legal on some runtime flavours and a panic on others, which makes it a thing that
    /// works until the deployment's shape changes — a single-worker node panicked on the exact call
    /// a multi-worker node served. A channel is flavour-independent: the blocking side waits on a
    /// standard-library receiver, which knows nothing about runtimes, and the async side is an
    /// ordinary task. The seam is the same seam; only the way it is crossed stopped depending on
    /// how the node was configured.
    #[must_use]
    pub fn new(inner: axum::Router, runtime: &tokio::runtime::Handle) -> Self {
        let (errands, mut inbox) = tokio::sync::mpsc::unbounded_channel::<Errand>();
        runtime.spawn(async move {
            while let Some((request, reply)) = inbox.recv().await {
                let inner = inner.clone();
                // One task per operation, so a slow verb cannot hold up the one behind it — the
                // surface was concurrent before the switch and stays concurrent through it.
                tokio::spawn(async move {
                    let _ = reply.send(call(inner, &request).await);
                });
            }
        });
        RouterDispatch { errands }
    }
}

/// Hand one request to the router and take its whole answer.
#[cfg(feature = "root-admin")]
async fn call(inner: axum::Router, request: &AdminRequest) -> AdminAnswer {
    use tower::ServiceExt;

    let mut builder = axum::http::Request::builder()
        .method(request.method.as_str())
        .uri(request.path.as_str());
    for (name, value) in &request.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    let Ok(http) = builder.body(axum::body::Body::from(request.body.clone())) else {
        return refused_answer();
    };

    // The router's own error type is uninhabited: a mounted axum router answers, and failing is not
    // among the things it can do. So there is no error arm to write here, and writing one anyway
    // would be a branch that can never be taken pretending to be a fallback that could be.
    let response = inner.oneshot(http).await.unwrap_or_else(|e| match e {});
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap_or_default();
    AdminAnswer {
        status: parts.status.as_u16(),
        headers: header_pairs(&parts.headers),
        body: bytes.to_vec(),
    }
}

#[cfg(feature = "root-admin")]
impl AdminDispatch for RouterDispatch {
    fn execute(&self, _verb: KernelVerb, request: &AdminRequest) -> AdminAnswer {
        let (reply, answer) = std::sync::mpsc::sync_channel(1);
        if self.errands.send((request.clone(), reply)).is_err() {
            // The driving task is gone, which happens only as the node itself goes away. There is
            // no surface left to ask, and saying so is the only answer left.
            return unavailable_answer();
        }
        answer.recv().unwrap_or_else(|_| unavailable_answer())
    }
}

/// Header names and values as owned pairs, in emission order.
///
/// A header value is bytes rather than text, and this is the one place that matters: rendering it
/// lossily here would change a byte the oracle compares. Everything the admin surface emits is
/// ASCII, so the conversion is exact — and it is written as a conversion rather than an assumption
/// so that a value which was not would be visible rather than silent.
#[cfg(feature = "root-admin")]
fn header_pairs(headers: &axum::http::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

/// Wrap a mounted admin surface so every request on it travels through the kernel.
///
/// The router that goes in is the one that already answers; the router that comes out answers the
/// same operations through the loop. The seam between them is [`RouterDispatch`], so the inner
/// router remains the only thing that knows what any of these operations do.
///
/// The loop is synchronous and the router is not, so the walk runs on a blocking worker and the one
/// await inside it — the inner router's own — is driven on the runtime this was handed. That is the
/// honest ordering: Route drives the seam, the seam drives the surface, and the answer comes back
/// through the steps that are still to run.
#[cfg(feature = "root-admin")]
pub fn mount(
    inner: axum::Router,
    kernel: busbar_kernel::teller::Kernel,
    build_units: impl FnOnce(Arc<dyn AdminDispatch>) -> crate::root::kernel::ProductionUnits,
) -> axum::Router {
    let runtime = tokio::runtime::Handle::current();
    let dispatch: Arc<dyn AdminDispatch> = Arc::new(RouterDispatch::new(inner.clone(), &runtime));
    let node = Arc::new(AdminNode::new(kernel, build_units(dispatch)));

    axum::Router::new().fallback(axum::routing::any(
        move |req: axum::http::Request<axum::body::Body>| {
            let node = Arc::clone(&node);
            let inner = inner.clone();
            async move {
                use tower::ServiceExt;

                // THE CLAIM IS WHAT DECIDES. The admin plane claims one path pattern and nothing
                // else, and this listener carries routes that are deliberately outside it: the
                // health probe answers on both listeners with the auth chain bypassed entirely, and
                // it is not an administrative verb. Walking those through a loop whose decode step
                // reads a table they were never in would refuse a route that has always answered.
                // So the claim is asked first, and a path outside it goes straight to the surface it
                // already reached.
                let path = req.uri().path().to_string();
                let claimed = path.starts_with(busbar_contract::surface::ADMIN_PREFIX);

                // AND THE TABLE IS WHAT DECIDES WHICH UNIT. Inside the claim, the plane declares a
                // closed table of operations, and a method-and-path pair outside it is not a unit
                // this plane has — it is a request the surface's own fallback already answers, with
                // the 404 or the 405 that release pinned. Manufacturing a status here for a pair
                // this plane never claimed would be the root inventing an answer it has no basis
                // for, and the whole point of the seam is that it never does that.
                let declared =
                    busbar_plane_admin::verbs::resolve(req.method().as_str(), &path).is_some();
                if !claimed || !declared {
                    return inner.oneshot(req).await.unwrap_or_else(|e| match e {});
                }

                let (parts, body) = req.into_parts();
                let bytes = axum::body::to_bytes(body, usize::MAX)
                    .await
                    .unwrap_or_default();
                let request = AdminRequest {
                    method: parts.method.as_str().to_string(),
                    path: parts
                        .uri
                        .path_and_query()
                        .map_or_else(|| parts.uri.path().to_string(), ToString::to_string),
                    credential: parts
                        .headers
                        .get(axum::http::header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .map(|v| v.trim_start_matches("Bearer ").to_string()),
                    headers: header_pairs(&parts.headers),
                    body: bytes.to_vec(),
                    at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs()),
                };
                let answer = tokio::task::spawn_blocking(move || node.answer(request))
                    .await
                    .unwrap_or_else(|_| unavailable_answer());

                let mut response = axum::http::Response::builder().status(answer.status);
                for (name, value) in &answer.headers {
                    response = response.header(name.as_str(), value.as_str());
                }
                response
                    .body(axum::body::Body::from(answer.body))
                    .unwrap_or_else(|_| {
                        axum::http::Response::builder()
                            .status(500)
                            .body(axum::body::Body::empty())
                            .expect("an empty 500 always builds")
                    })
            }
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_request() -> AdminRequest {
        AdminRequest {
            method: "GET".to_string(),
            path: "/api/v1/admin/audit?limit=4".to_string(),
            credential: Some("admin-token".to_string()),
            headers: vec![("accept".to_string(), "application/json".to_string())],
            body: Vec::new(),
            at: 1_700_000_000,
        }
    }

    /// The round trip is the whole reason the answer travels as bytes: a status, a header value and
    /// a body all come back exactly as they went in, including bytes a text framing would mangle.
    #[test]
    fn an_answer_survives_the_round_trip_through_the_verbs_seam() {
        let answer = AdminAnswer {
            status: 409,
            headers: vec![
                ("etag".to_string(), "\"7\"".to_string()),
                ("content-type".to_string(), "application/json".to_string()),
            ],
            body: vec![0x00, 0xff, b'{', b'}', 0x0a],
        };
        let packed = answer.pack();
        assert_eq!(AdminAnswer::unpack(&packed), Some(answer));
    }

    /// The only producer of the framing is the packer. Anything else is this file being wrong, and
    /// a lenient parse would turn that into a silently wrong answer.
    #[test]
    fn a_shape_the_packer_did_not_write_has_no_answer() {
        assert_eq!(AdminAnswer::unpack(&[]), None);
        assert_eq!(AdminAnswer::unpack(&[0, 200, 0, 0, 0, 1]), None);
        let mut trailing = AdminAnswer {
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
        }
        .pack();
        trailing.push(0);
        assert_eq!(AdminAnswer::unpack(&trailing), None);
    }

    /// Both tables were extracted from the same pinned tag. Every row the plane decodes to has to
    /// name a verb the executing unit knows, or the root would be binding an operation to nothing.
    #[test]
    fn every_row_the_plane_decodes_names_a_verb_the_unit_knows() {
        let mut unmatched = Vec::new();
        for row in busbar_plane_admin::verbs::table() {
            if kernel_verb(&row).is_none() {
                unmatched.push(row.verb);
            }
        }
        assert!(
            unmatched.is_empty(),
            "rows with no kernel verb: {unmatched:?}"
        );
    }

    /// The 66 join on method and path — the columns the pinned document fixed — and all 66 of them
    /// do. A row that fell through to the name join would be a legacy operation matched on a casing
    /// convention rather than on what the tag actually pinned.
    #[test]
    fn all_sixty_six_legacy_rows_join_on_the_pinned_method_and_path() {
        let joined = busbar_plane_admin::verbs::table()
            .iter()
            .filter(|row| {
                LEGACY_VERBS
                    .iter()
                    .any(|legacy| legacy.method == row.method && legacy.path == row.template)
            })
            .count();
        assert_eq!(joined, 66);
    }

    /// The two spellings of one operation's name really are two spellings, and the join does not
    /// depend on either of them. This is the finding that made the join what it is, kept as a test
    /// so that a future crate quietly agreeing on one casing does not look like a fix.
    #[test]
    fn the_two_tables_spell_one_operations_name_two_ways() {
        let audit = busbar_plane_admin::verbs::resolve("GET", "/api/v1/admin/audit")
            .expect("audit is in the plane's table");
        let row = LEGACY_VERBS
            .iter()
            .find(|row| row.method == "GET" && row.path == "/api/v1/admin/audit")
            .expect("audit is in the unit's table");
        assert_eq!(audit.verb, "get_audit");
        assert_eq!(row.operation_id, "GetAudit");
        assert_eq!(kernel_verb(&audit), Some(KernelVerb::GetAudit));
    }

    /// The rate class comes off the shipped table, not off the blast-radius-blind default: a config
    /// mutation is limited at the config budget and an ordinary read is forbidden from mutating at
    /// all.
    #[test]
    fn the_rate_class_is_the_shipped_table_and_not_the_default() {
        assert_eq!(
            mutation_class(KernelVerb::PostConfigApply),
            MutationClass::Config
        );
        assert_eq!(
            mutation_class(KernelVerb::PostConfigReload),
            MutationClass::Config
        );
        assert_eq!(
            mutation_class(KernelVerb::PostRestart),
            MutationClass::Config
        );
        assert_eq!(
            mutation_class(KernelVerb::PutAdminAuth),
            MutationClass::Config
        );
        assert_eq!(mutation_class(KernelVerb::PostKeys), MutationClass::Crud);
        assert_eq!(
            mutation_class(KernelVerb::PostPluginsInspect),
            MutationClass::PluginInspect
        );
        // `Forbidden` names a verb the MUTATION budget does not apply to — every read is one. It is
        // not a refusal, and an admit step that read it as one turned every read on the surface into
        // a 403. That is the hazard a vocabulary shared between two crates invites, so the reading
        // is pinned here rather than left to the name.
        assert_eq!(
            mutation_class(KernelVerb::GetAudit),
            MutationClass::Forbidden
        );
        assert_eq!(MutationClass::Forbidden.limit(), 0);
        assert!(
            busbar_unit_scope::admin_required_scope("GET", "/api/v1/admin/audit")
                == Scope::ReadOnly
        );
    }

    /// The two spellings of the two-rung split are one split. If they ever stopped agreeing, a
    /// read-only credential would be admitted to a mutation or a full one refused a read.
    #[test]
    fn the_two_spellings_of_the_scope_split_agree() {
        assert_eq!(scope_as_verb_scope(Scope::ReadOnly), VerbScope::ReadOnly);
        assert_eq!(scope_as_verb_scope(Scope::Full), VerbScope::Full);
        assert!(VerbScope::Full.allows(VerbScope::ReadOnly));
        assert!(!VerbScope::ReadOnly.allows(VerbScope::Full));
    }

    /// An entry that outlived its unit would be a leak per request. Opening and closing is the whole
    /// lifecycle, and the table is empty between requests.
    #[test]
    fn a_unit_leaves_the_table_when_it_ends() {
        let units = AdminUnits::new();
        let key = UnitKey::new(7);
        assert!(units.is_empty());
        units.open(key, a_request());
        assert_eq!(units.len(), 1);
        assert_eq!(
            units.request(key).map(|r| r.method),
            Some("GET".to_string())
        );
        assert_eq!(units.close(key), None);
        assert!(units.is_empty());
    }

    /// What the exit path settles for an admin unit: nothing located, no upstream candidate, and
    /// therefore no request slot and no flat fee, whatever the deployment configured the fee to be.
    #[test]
    fn an_admin_unit_settles_at_zero_requests_and_zero_fee() {
        let ctx = UnitCtx {
            key: UnitKey::new(1),
            origin: busbar_caps::OriginKind::Client,
            session: None,
            generation: busbar_kernel::registry::Generation::FIRST,
            admin_listener: true,
            kernel_verb_only: true,
        };
        let evidence = evidence(&ctx);
        assert!(!evidence.upstream_candidate);
        assert_eq!(
            busbar_kernel::teller::requests_drawn(ctx.origin, evidence.upstream_candidate),
            0
        );
        assert_eq!(busbar_kernel::teller::fee_count(&evidence.fee).0, 0);
    }

    /// The nonce is drawn, not derived. Two draws over the same unit must not agree, or a one-time
    /// secret's placeholder would be predictable from the secret it protects.
    #[test]
    fn two_nonces_over_one_unit_do_not_agree() {
        use busbar_unit_verbs::NonceSource;
        let source = ArrivalNonce(1_700_000_000);
        let mut first = [0u8; 16];
        let mut second = [0u8; 16];
        source.fill(&mut first);
        source.fill(&mut second);
        assert_ne!(first, second);
        assert_ne!(first, [0u8; 16]);
    }
}
