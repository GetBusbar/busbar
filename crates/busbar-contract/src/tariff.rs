// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **WHAT A DEPLOYMENT'S COUNTS ARE WORTH**, as data, in one place every side may name.
//!
//! A tariff has two halves and they live apart on purpose. The COUNTS — how many visits, how many
//! transactions, whether the meter's quantities are charged for — are the teller's, and it holds no
//! amount. The AMOUNTS are the dated card's, and the card holds no count. What crosses between the
//! configuration that declares them and the card that applies them is THIS: a record of figures in
//! a currency's minor units, and the rule for a fraction of one.
//!
//! It is declared HERE, in the contract, for the same reason every other closed grammar in this
//! crate is: the engine that PARSES a deployment's configuration, the seam that CARRIES the result
//! and the unit that APPLIES it may not name each other. A record in the retiring engine would be a
//! name three crates had to learn and then unlearn; a record in the unit that prices would make the
//! seam depend on the card's shape. So the figures are contract data, spoken by everyone, owned by
//! nobody, and they carry no card, no currency and no count.

use serde::Deserialize;

/// **WHICH WAY A FRACTION OF A MINOR UNIT GOES.** Declared by the deployment, never implied.
///
/// A rate of `amount per N units` produces a fraction whenever the quantity is not a multiple of N,
/// and somebody has to decide the direction. The default is [`Rounding::Bankers`] — half to even,
/// the rule a till uses — because it is the only one of the three with no bias: rounding up is the
/// house taking a systematic cut of every fraction it ever sees, and rounding down is the customer
/// taking the same cut back.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rounding {
    /// Half to even — the teller's rule, and the default.
    #[default]
    Bankers,
    /// Away from zero. The house takes every fraction.
    Up,
    /// Toward zero. The customer takes every fraction.
    Down,
}

impl Rounding {
    /// Divide, and resolve the remainder the way this rule says.
    ///
    /// The arithmetic lives ON the declaration rather than beside it, because a rule that says which
    /// way a fraction goes and a function that sends it that way are one thing: two readers each
    /// carrying their own division is how one request comes to be judged at one figure and billed
    /// at another. Integer throughout — there is no floating point on any path that decides money.
    ///
    /// A `per` of nothing is refused by configuration validation before a schedule can carry one; if
    /// one arrives anyway the answer is nothing rather than a panic, because a division by zero
    /// inside a settlement would take a node down for a configuration mistake.
    #[must_use]
    pub fn divide(self, numerator: i128, per: u64) -> i128 {
        let per = i128::from(per);
        if per <= 0 {
            return 0;
        }
        let whole = numerator / per;
        let rest = numerator % per;
        if rest == 0 {
            return whole;
        }
        match self {
            Rounding::Down => whole,
            Rounding::Up => whole + 1,
            // Half to even: below half rounds down, above half rounds up, and exactly half goes to
            // whichever of the two neighbours is even — which is what removes the bias.
            Rounding::Bankers => match (rest * 2).cmp(&per) {
                std::cmp::Ordering::Less => whole,
                std::cmp::Ordering::Greater => whole + 1,
                std::cmp::Ordering::Equal => whole + i128::from(whole % 2 != 0),
            },
        }
    }
}

/// **AN AMOUNT PER N UNITS OF ONE DECLARED DIMENSION.**
///
/// `per` is carried rather than folded into the rate, because "3 cents per 1000 tokens" is the
/// schedule operators publish and a rate expressed as a fraction of a cent is a rounding decision
/// taken before anybody could declare one. The division happens once, where the schedule is
/// applied, under [`Rounding`].
///
/// `dimension` is a meter class some PLANE declared. There is no list of dimension names in this
/// file and there is not going to be one: a dimension exists exactly when a plane's own
/// declaration says it does.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerUnitTerm {
    /// The dimension's key, as the plane that declared it spells it.
    pub dimension: String,
    /// How many units one charge covers. At least one.
    pub per: u64,
    /// What one `per` units costs, in the currency's minor units.
    ///
    /// SPELLED `cents` WHERE AN OPERATOR WRITES IT and `amount` where the tree reads it, on purpose.
    /// A deployment's file says cents because that is the word for the figure it is writing; the
    /// type says amount because the figure is in whatever the currency's minor unit is, and `cents`
    /// on a non-USD deployment is a lie — which is the same correction the card already made when
    /// it stopped spelling its own fee `per_request_fee_cents`.
    #[serde(rename = "cents")]
    pub amount: i64,
}

/// **ONE DEPLOYMENT'S FEE TERMS IN ONE CURRENCY.** Every figure in that currency's MINOR units.
///
/// It holds no count, and whatever decides the counts holds no amount: counts and amounts never
/// live in one type, so there is no value anywhere that could be read as either. It names no lane,
/// no plane and no currency — a currency is the card's to know, and these figures are the same
/// figures whichever card carries them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeeTerms {
    /// What one admitted visit costs.
    pub entry: i64,
    /// What one completed transaction costs, flat.
    pub transaction: i64,
    /// What the units cost, per dimension. Empty is the shipped default, and it is what leaves a
    /// card's own per-(lane, class) rates the only thing pricing a unit of a dimension.
    pub per_units: Vec<PerUnitTerm>,
    /// The floor under one unit's tariff charge.
    pub minimum: i64,
    /// The cap over it; `None` is uncapped, which is a different statement from a cap of nothing.
    pub maximum: Option<i64>,
    /// Which way a fraction of a minor unit goes.
    pub rounding: Rounding,
}

impl FeeTerms {
    /// **THE PREVIOUS RELEASE'S TERMS**: one figure, charged for the visit and for the transaction
    /// alike, nothing per unit, no floor and no cap.
    ///
    /// Named so the compatibility claim is a VALUE rather than a comment: a deployment that wrote
    /// only the previous release's one fee key is charged by exactly this, and the cells that prove
    /// it construct it here rather than restating five zeroes each. Clamped at nothing, once, on the
    /// one constructor that makes terms out of a single number: no unit may ever bill a negative
    /// amount, which would credit a budget back toward headroom.
    #[must_use]
    pub fn flat(amount: i64) -> Self {
        FeeTerms {
            entry: amount.max(0),
            transaction: amount.max(0),
            ..FeeTerms::default()
        }
    }
}

/// **WHICH OF THE FOUR SCOPES A SCHEDULE WAS RESOLVED AT.** The word, without the key.
///
/// The order is the resolution order, innermost first, and it is declared once here so that nothing
/// downstream carries a second copy of "tier beats pool beats plane beats default".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScopeKind {
    /// The node's own schedule — what a deployment that scoped nothing is charged under.
    #[default]
    Default,
    /// A plane kind's schedule, keyed by the plane's own registry key.
    Plane,
    /// A pool's schedule, keyed by the pool a unit was routed to.
    Pool,
    /// A tier's schedule, keyed by the group a unit's chain was admitted under.
    Tier,
}

impl ScopeKind {
    /// The word an operator writes and a posting records.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            ScopeKind::Default => "default",
            ScopeKind::Plane => "plane",
            ScopeKind::Pool => "pool",
            ScopeKind::Tier => "tier",
        }
    }

    /// The kind that word names, or `None`. NEVER a fallback: a word this does not know is a
    /// scope nobody declared, and answering `default` for it would price a unit under a schedule
    /// its own row says it was not charged under.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        [
            ScopeKind::Default,
            ScopeKind::Plane,
            ScopeKind::Pool,
            ScopeKind::Tier,
        ]
        .into_iter()
        .find(|k| k.word() == word)
    }
}

/// **THE SCOPE ONE UNIT'S AMOUNTS WERE RESOLVED AT**, recorded on the posting that carries them.
///
/// A bill must be re-derivable from what was written down and from nothing else. The counts are on
/// the posting and the amounts are on the dated card, and until a posting said WHICH schedule it was
/// charged under there was exactly one schedule a card could carry — the node's — because a reader
/// re-pricing the row had no way to choose a second. This is that missing field: the scope, as a
/// kind and a key, so a pool's or a tier's own figures can be applied at settlement and re-derived
/// by an auditor a year later.
///
/// **ONE SCOPE, NOT A CHAIN.** What a posting records is the INNERMOST scope that applied to the
/// unit, and the schedule the card holds under that scope is what it was charged. A posting that
/// recorded a chain would be recording the unit's routing rather than the schedule it was billed
/// under, and a reader would have to re-walk a configuration that may since have changed to find
/// out what it paid. Whatever the innermost scope does not say it takes from the node's own
/// default — never from a third schedule the row did not name.
///
/// A row that carries no scope at all is a row from the previous release, and it reads
/// [`ScopeKind::Default`]: there was no other schedule for it to have been charged under.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TariffScope {
    /// Which of the four.
    pub kind: ScopeKind,
    /// The name under that kind — the plane key, the pool name or the group. Empty at
    /// [`ScopeKind::Default`], which is keyed by nothing because there is only one of it.
    pub key: String,
}

impl TariffScope {
    /// The node's own scope: what a unit no narrower schedule applied to is charged under.
    #[must_use]
    pub fn node() -> Self {
        TariffScope::default()
    }

    /// A plane kind's scope.
    #[must_use]
    pub fn plane(key: impl Into<String>) -> Self {
        TariffScope {
            kind: ScopeKind::Plane,
            key: key.into(),
        }
    }

    /// A pool's scope.
    #[must_use]
    pub fn pool(key: impl Into<String>) -> Self {
        TariffScope {
            kind: ScopeKind::Pool,
            key: key.into(),
        }
    }

    /// A tier's scope, keyed by the group.
    #[must_use]
    pub fn tier(key: impl Into<String>) -> Self {
        TariffScope {
            kind: ScopeKind::Tier,
            key: key.into(),
        }
    }

    /// **THE ROW ENCODING**: `default`, or `<kind>:<key>`.
    ///
    /// One spelling, declared beside the type that means it, so the journal row, an operator's
    /// configuration path and an audit answer cannot come apart. Read back by [`Self::decode`].
    #[must_use]
    pub fn encoded(&self) -> String {
        if self.kind == ScopeKind::Default {
            ScopeKind::Default.word().to_string()
        } else {
            format!("{}:{}", self.kind.word(), self.key)
        }
    }

    /// **READ A ROW'S SCOPE BACK.** An ABSENT field — the empty string, which is what a row written
    /// before this field existed yields — is the node's own scope, because that is the only
    /// schedule such a row could have been charged under.
    ///
    /// Anything else this cannot read is `None` rather than a default: a row naming a scope nobody
    /// can resolve must be reported, never silently re-priced under a schedule it does not name.
    #[must_use]
    pub fn decode(encoded: &str) -> Option<Self> {
        if encoded.is_empty() || encoded == ScopeKind::Default.word() {
            return Some(TariffScope::node());
        }
        let (word, key) = encoded.split_once(':')?;
        let kind = ScopeKind::parse(word)?;
        if kind == ScopeKind::Default || key.is_empty() {
            return None;
        }
        Some(TariffScope {
            kind,
            key: key.to_string(),
        })
    }
}

/// **ONE DEPLOYMENT'S TERMS AT EVERY SCOPE IT WROTE ONE FOR**, as the dated card carries them.
///
/// The node's own terms, and one further set per scope an operator scoped. A card holds this rather
/// than a single [`FeeTerms`] for one reason: the amounts are the card's, the card is dated, and a
/// posting now records which scope it was charged at — so the card must be able to answer for that
/// scope at read time, or the scope on the row would name a schedule nothing could look up.
///
/// A scope this does not carry answers the node's own terms. That is not a silent zero: it is the
/// same answer the resolution itself gives for a scope nobody configured, and the posting still
/// says which scope was asked for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopedFeeTerms {
    node: FeeTerms,
    scoped: std::collections::BTreeMap<TariffScope, FeeTerms>,
}

impl ScopedFeeTerms {
    /// A card's terms with one schedule: the node's. What a deployment that scoped no amounts has.
    #[must_use]
    pub fn node(terms: FeeTerms) -> Self {
        ScopedFeeTerms {
            node: terms,
            scoped: std::collections::BTreeMap::new(),
        }
    }

    /// Add one scope's already-resolved schedule.
    #[must_use]
    pub fn with(mut self, scope: TariffScope, terms: FeeTerms) -> Self {
        self.scoped.insert(scope, terms);
        self
    }

    /// **THE SCHEDULE A POSTING AT THIS SCOPE IS CHARGED UNDER.** One lookup, no arithmetic.
    #[must_use]
    pub fn at(&self, scope: &TariffScope) -> &FeeTerms {
        self.scoped.get(scope).unwrap_or(&self.node)
    }

    /// The node's own terms.
    #[must_use]
    pub fn node_terms(&self) -> &FeeTerms {
        &self.node
    }
}
