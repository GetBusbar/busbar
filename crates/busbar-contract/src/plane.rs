//! The plane kind: what bytes mean. A plane names a transport only as a claim, never holds a
//! connection, names no unit or other plane except through a nested destination, and returns
//! facts and locators only — never an amount, a decision, a credential, a price or a scheme
//! outside its claim. Pure over its inputs; no default bodies (see `docs/design/BUSBAR-1.6.0.md` #38).

use crate::ids::OpClassId;

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
    /// The operation classes this plane serves ONE LEVEL DOWN — to another plane's unit that states
    /// only the class it needs ([`crate::dest::DestinationFacts::NestedPlane`]) — each with the name
    /// the plane is called by where a refusal names it. The host answers a nested destination with
    /// the plane that declares the class here; at most one plane declares a class
    /// ([`check_served_op_classes`]). `&[]` for a plane no other plane reaches.
    pub served_op_classes: &'static [ServedOpClass],
    /// The plane-record KINDS this plane keeps on the store's neutral plane-record seam (the
    /// `PlaneRecord::kind` tags it writes). The administrative `plane_record_write` verb writes a
    /// record of a kind only if the named plane declares it here ([`declares_record_kind`]), so an
    /// operator cannot land a record under another plane's kind or a kind no plane reads. `&[]`
    /// for a plane that keeps none.
    pub record_kinds: &'static [&'static str],
    /// The top-level config sections this plane REQUIRES a document to carry — the ones it owns or
    /// consumes (`models` for the plane that owns it, `providers` for a plane that resolves its
    /// targets through that catalog). A document omitting one is refused with the config grammar's
    /// own missing-field message for it; a section no registered plane lists may be omitted. `&[]`
    /// for a plane that requires none.
    pub required_config_sections: &'static [&'static str],
    /// The per-registration keys of [`Self::config_section`] the HOST parses for the trust
    /// lifecycle (the tail's `trust_keys`): the pin and the re-verification cadence. The plane's own
    /// validator does not read them. At most one key per [`TrustRole`]. `&[]` for a plane whose
    /// registrations carry no trust root.
    pub trust_keys: &'static [TrustKeyDecl],
    /// The plane's own sentence refusing the reserved `upstream_credentials: passthrough` section
    /// default (the tail's `caller_credential_refusal`). The kernel emits it verbatim when a
    /// section's default forwards the caller's credential, so the plane owns its words and the
    /// kernel names only the reserved key. `None` for a plane on which forwarding it is legitimate.
    pub caller_credential_refusal: Option<&'static str>,
}

/// Which trust-lifecycle fact a [`TrustKeyDecl`] holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustRole {
    /// The pin object, `{mechanism, key?, fingerprint?}`.
    Pin,
    /// The longest a verification may be reused, a `<n><s|m|h|d>` duration.
    ReverifyTtl,
    /// How long after a drift a clean answer is disbelieved, a `<n><s|m|h|d>` duration.
    RecoveryBackoff,
    /// The registration's private reach, a boolean (`abi::plane::TRUST_PRIVATE_REACH`).
    PrivateReach,
    /// The registration's configured item approvals, `{<item>: {<field>: "<digest>"}}`, the field
    /// named by [`TrustKeyDecl::default`] (`abi::plane::TRUST_ITEM_APPROVALS`).
    ItemApprovals,
}

/// One pin mechanism a [`TrustRole::Pin`] key accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinMechanismDecl {
    /// The config token the operator writes.
    pub token: &'static str,
    /// True when the mechanism is an authenticity root, and so needs key material; false for the
    /// no-root spelling, which must carry none.
    pub root: bool,
    /// True when the mechanism's material is the far end's KEY (a pin of its certificate's
    /// SubjectPublicKeyInfo): the host seals it into the registration's trust anchors and the
    /// connector enforces it on every connection (`abi::plane::MECHANISM_PEER_KEY`).
    pub peer_key: bool,
}

/// One per-registration key the host parses for the trust lifecycle ([`PlaneDeclaration::trust_keys`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustKeyDecl {
    /// The key, as written inside one registration.
    pub key: &'static str,
    /// What it holds.
    pub role: TrustRole,
    /// A pin only: the pin object may also carry `fingerprint`.
    pub fingerprint: bool,
    /// A duration key's value when a registration writes none; `None` = zero. A pin has none. An
    /// item-approvals key: the field of each item's object holding its approved digest.
    pub default: Option<&'static str>,
    /// A pin's mechanisms; `&[]` for a duration key.
    pub mechanisms: &'static [PinMechanismDecl],
}

/// Whether `decl` declares it keeps plane records of `kind` ([`PlaneDeclaration::record_kinds`]).
#[must_use]
pub fn declares_record_kind(decl: &PlaneDeclaration, kind: &str) -> bool {
    decl.record_kinds.contains(&kind)
}

/// One operation class a plane serves one level down, and the plane's DECLARED display name — the
/// words a refusal that names the class's server reads, so the requesting plane spells no plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServedOpClass {
    /// The operation class served.
    pub op: OpClassId,
    /// The display name the serving plane is called by in operator- and caller-visible text.
    pub name: &'static str,
}

/// THE ONE-SERVER GUARD over a set of declarations' [`PlaneDeclaration::served_op_classes`]: `Ok(())`
/// when no operation class is declared by two planes (or twice by one), else the first refusal.
/// A class two planes serve would make the answer to a nested destination a matter of fold order.
pub fn check_served_op_classes(decls: &[&PlaneDeclaration]) -> Result<(), String> {
    let mut seen: std::collections::BTreeMap<OpClassId, &str> = std::collections::BTreeMap::new();
    for decl in decls {
        for s in decl.served_op_classes {
            if let Some(other) = seen.insert(s.op, decl.key) {
                return Err(format!(
                    "plane `{}` declares it serves operation class `{}`, which plane `{other}` \
                     serves too: a nested destination names a class, and one class has one server",
                    decl.key, s.op
                ));
            }
        }
    }
    Ok(())
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

/// THE CONDITION OF A REFUSED ADMIN ANSWER: the reply head field a door's `serve` names, beside a
/// `400`, which of the admin taxonomy's validation conditions the refusal is, so the kernel frames
/// it condition-tagged. Absent = untagged.
pub const ADMIN_CONDITION_FIELD: &str = "busbar-admin-condition";

/// [`ADMIN_CONDITION_FIELD`]: the request body did not parse as the verb's expected shape.
pub const ADMIN_CONDITION_MALFORMED_BODY: &str = "malformed-body";

/// [`ADMIN_CONDITION_FIELD`]: the request contradicts the operator's configured state.
pub const ADMIN_CONDITION_INVALID_CONFIG: &str = "invalid-config";

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

#[cfg(test)]
#[path = "tests/served_op_class_tests.rs"]
mod served_op_class_tests;
