// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Hold sizing.
//!
//! The hold is ACCOUNTING. It sizes the ledger's reservation for a unit that has already been
//! admitted; it is not a second door and it never refuses a unit the decision admitted. If it
//! turns out to be too small the unit tops it up, and if there is nothing to top up from the unit
//! still runs to its end and posts the excess. Nothing here can make a request fail that would
//! otherwise have succeeded — which is exactly why the hold's conservatism is invisible to a
//! caller and does not need a parity exception.
//!
//! The size is the per-class estimated quantity times the most expensive unit price for that class
//! over the destinations the unit may reach, summed, plus the flat fee as its own line, all
//! multiplied by the chain's tier and rounded UP once.
//!
//! ## Where the prices come from
//!
//! From the card the ROOT PINNED at admission, resolved out of that pinned snapshot at the unit's
//! own arrival instant — never from a history read later. A hold sized against a card that was
//! appended while the request was in flight would be a reservation for a price the request was never
//! judged at, and the whole point of the pin is that an apply landing mid-body cannot change what a
//! request in flight is reading.
//!
//! The arithmetic is the cost unit's, once: the per-class multiply-and-sum is
//! [`busbar_unit_cost::price_at_card`], reached with the card already resolved, so the door cannot
//! carry a second copy of the multiply that a clamp or a rounding change could land on one side of.
//! What the door adds is the ONE thing a hold does differently, and it is deliberate: the tier
//! rounds UP here where pricing truncates. A hold is a reservation, and over-reserving costs a
//! caller nothing but headroom it gives straight back at settlement, where over-billing is money.

// contract: Estimate { per_class } is a type the contract crate owns. It is declared here so the
// door has something to size against while the crates land side by side.

use busbar_unit_cost::{
    price_at_card, CurrencyCode, HistorySeq, HistoryView, Posting, Quantity, RateCard, Unpriceable,
};

/// How many basis points make one whole unit — the divisor that turns a tier expressed in basis
/// points back into a multiplier. A tier of 10 000 basis points is a multiplier of one, so a hold
/// sized at the full tier is the pre-tier sum unchanged.
///
/// Named rather than written at the divide, because a bare ten thousand at the bottom of a
/// money calculation is indistinguishable from a rounding scale or a percentage-times-hundred, and
/// the three are not interchangeable.
const BASIS_POINTS_PER_UNIT: u128 = 10_000;

/// One meter class's contribution to the estimate: how much of it the unit is expected to consume,
/// and the highest price any destination it may reach charges for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassEstimate {
    /// The meter class this line is for.
    pub class: String,
    /// The estimated quantity, in the class's own units, already converted from bytes through the
    /// class's divisor by the caller.
    pub quantity: u64,
    /// The highest per-unit price, in nano-units, over the verified destination set. The maximum,
    /// not the mean: a hold that is too small has to top up, and a hold that is too large costs
    /// nothing but headroom the unit gives straight back at settlement.
    pub max_unit_price_nanos: u64,
}

/// What the unit is expected to consume, per meter class, plus the flat fee line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Estimate {
    /// One line per meter class.
    pub per_class: Vec<ClassEstimate>,
    /// The flat per-request fee line, in nano-units, already zero for every unit that does not
    /// pay one — a provider push, a heartbeat, a kernel verb.
    pub fee_nanos: u64,
}

impl Estimate {
    /// An estimate with nothing in it: the shape of a unit priced at zero.
    pub fn zero() -> Self {
        Self::default()
    }

    /// The summed pre-tier size, in nano-units, before the chain's multiplier is applied.
    pub fn pre_tier_nanos(&self) -> u128 {
        let mut total: u128 = self.fee_nanos as u128;
        for line in &self.per_class {
            total =
                total.saturating_add((line.quantity as u128) * (line.max_unit_price_nanos as u128));
        }
        total
    }

    /// The hold size in nano-units: the pre-tier sum times the chain's tier in basis points,
    /// rounded UP once over the whole sum — one divide, never a sum of per-line ceilings, so the
    /// figure does not drift with how the estimate happened to be split into lines.
    pub fn hold_nanos(&self, tier_bp: u32) -> u64 {
        ceil_tier(self.pre_tier_nanos(), tier_bp)
    }

    /// **THE POSTING THE ESTIMATE STANDS FOR**: the per-class quantities on one lane, at the unit's
    /// arrival instant, marked estimated.
    ///
    /// `estimated` is `true` and there is no argument that could make it anything else. An estimate
    /// IS the kernel's own floor rather than a figure a destination reported — that is the whole
    /// definition of the type — and a posting built from one that claimed otherwise would tell the
    /// ledger a reservation was a measurement.
    ///
    /// No price is read here. The posting carries quantities and an instant, which is exactly what a
    /// lookup takes, and the lane is on it because the card is keyed by lane: a posting that kept no
    /// lane could not be priced by a lookup at all.
    pub fn as_posting(
        &self,
        lane: &str,
        fee_count: u64,
        tier_bp: u32,
        arrived_ms: u64,
        arrived_mono: u64,
    ) -> Posting {
        Posting {
            lane: lane.to_string(),
            quantities: self
                .per_class
                .iter()
                .map(|line| Quantity::new(line.class.as_str(), line.quantity))
                .collect(),
            fee_count,
            tier_bp,
            arrived_ms,
            arrived_mono,
            estimated: true,
            cached: None,
        }
    }

    /// Size the hold against ONE resolved card: the lookup's pre-tier sum, through the ceiling.
    ///
    /// The card and its sequence number arrive already resolved, so this cannot reach past the
    /// snapshot the door pinned. Every multiply and every sum belongs to
    /// [`busbar_unit_cost::price_at_card`]; the only arithmetic here is the ceiling, which is the
    /// hold's own and is the one place the two postures differ.
    ///
    /// The fee is the CARD's, in the asked-for currency, times the count of fees the unit carries —
    /// not the estimate's precomputed [`Estimate::fee_nanos`], which is what a caller that has no
    /// card to read falls back to.
    pub fn hold_nanos_at_card(
        &self,
        card_seq: HistorySeq,
        card: &RateCard,
        ctx: &HoldContext<'_>,
        lane: &str,
    ) -> Result<u64, Unpriceable> {
        let posting = ctx.posting_for(self, lane);
        let priced = price_at_card(card_seq, card, &posting, ctx.currency)?;
        Ok(ceil_tier(priced.pre_tier_nanos, ctx.tier_bp))
    }

    /// **THE SIZING THE DOOR PERFORMS**: price the estimate through the card the pinned snapshot
    /// resolves at the unit's arrival instant, and never through a history read later.
    ///
    /// Over a destination set the answer is the MAXIMUM over the lanes the unit may reach, not the
    /// mean and not the first: a hold that is too small has to top up, and a hold that is too large
    /// costs nothing but headroom the unit gives straight back at settlement.
    ///
    /// **It cannot refuse.** Every arm returns a size. A snapshot with no entry covering the instant
    /// is not a refusal here — it is the 1.5.5 fee-only posture, where token pricing is zero
    /// everywhere and the flat fee still applies, which is precisely what a 1.5.5 deployment with no
    /// rate card configured does. A hole in the history fails closed at SETTLEMENT, where refusing
    /// costs a caller nothing that was already served; failing closed here would refuse a request
    /// 1.5.5 admitted, which is the one thing the door is not allowed to do. The posture is reported
    /// rather than swallowed, so the caller records the condition it could not have seen otherwise.
    pub fn size_at_arrival(&self, view: &HistoryView<'_>, ctx: &HoldContext<'_>) -> HoldSize {
        let Some((card_seq, card)) = view.card_at(ctx.arrived_ms) else {
            return HoldSize {
                nanos: self.fee_only_nanos(ctx.tier_bp),
                posture: HoldPosture::NoCardInForce { at: ctx.arrived_ms },
            };
        };
        let mut nanos: u64 = 0;
        for lane in ctx.lanes {
            match self.hold_nanos_at_card(card_seq, card, ctx, lane) {
                Ok(size) => nanos = nanos.max(size),
                // A card that does not name the node's currency is a BOOT refusal, not a request
                // one: by the time a unit is at the door the node has already declared the one
                // currency it reasons in. Reaching it here means the pinned entry cannot price that
                // currency, and the answer is the fee-only size and a named posture — never a
                // conversion out of a currency the card does price, which is a cross-rate, and never
                // a refusal of a unit 1.5.5 would have admitted.
                Err(Unpriceable::CurrencyNotPriced { card_seq, currency }) => {
                    return HoldSize {
                        nanos: self.fee_only_nanos(ctx.tier_bp),
                        posture: HoldPosture::CurrencyNotPriced { card_seq, currency },
                    };
                }
                // A present card silent about the lane prices its classes at nothing and says so;
                // `price_at_card` reports that on the answer rather than as an error, and the
                // fail-closed rule for it is the door's own (`Pricer::model_unpriced`), where it has
                // been since 1.5.5. Sizing does not duplicate it.
                Err(_) => {}
            }
        }
        HoldSize {
            nanos,
            posture: HoldPosture::Priced { card_seq },
        }
    }

    /// The fee-only size: the flat fee alone, through the same single ceiling.
    ///
    /// The 1.5.5 posture for a deployment that configured no rate card — token classes price at
    /// nothing and the fee still bills — reached here whenever no card can be resolved.
    fn fee_only_nanos(&self, tier_bp: u32) -> u64 {
        ceil_tier(u128::from(self.fee_nanos), tier_bp)
    }
}

/// The chain's tier applied to a pre-tier sum, ROUNDED UP, once, over the whole sum.
///
/// One divide, never a sum of per-line ceilings, so the figure does not drift with how the estimate
/// happened to be split into lines. Single-sited so that every path that sizes a hold — the estimate
/// at its own prices, the lookup at a resolved card, and the fee-only fallback — rounds the same way.
fn ceil_tier(pre_tier_nanos: u128, tier_bp: u32) -> u64 {
    let scaled = pre_tier_nanos.saturating_mul(tier_bp as u128);
    let ceil = scaled.div_ceil(BASIS_POINTS_PER_UNIT);
    u64::try_from(ceil).unwrap_or(u64::MAX)
}

/// What the door knows about the unit it is sizing a hold for, at the instant that unit arrived.
///
/// Bound once, beside the pinned snapshot, so a straddling request cannot be sized against one
/// instant and priced against another.
#[derive(Debug, Clone, Copy)]
pub struct HoldContext<'a> {
    /// The lanes this unit may reach. The hold takes the dearest of them.
    pub lanes: &'a [&'a str],
    /// **THE NODE'S CURRENCY, AND THE ONLY ONE ADMISSION REASONS IN.** There is no second currency
    /// on this path and nothing here that could turn one into another.
    pub currency: CurrencyCode,
    /// How many flat fees this unit carries — one for a billable client request, zero for a
    /// provider push, a heartbeat or a kernel verb.
    pub fee_count: u64,
    /// The chain's tier multiplier, in basis points.
    pub tier_bp: u32,
    /// The unit's arrival instant as a wall clock reads it: the instant the history is resolved at.
    pub arrived_ms: u64,
    /// The unit's arrival instant as a monotonic clock reads it: what orders the record.
    pub arrived_mono: u64,
}

impl HoldContext<'_> {
    fn posting_for(&self, estimate: &Estimate, lane: &str) -> Posting {
        estimate.as_posting(
            lane,
            self.fee_count,
            self.tier_bp,
            self.arrived_ms,
            self.arrived_mono,
        )
    }
}

/// Which card sized a hold, or why none did.
///
/// Reported rather than swallowed: none of these arms is a refusal, and the two that are not
/// `Priced` are conditions an operator has to be able to see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldPosture {
    /// Priced through the entry the pinned snapshot resolved at the unit's arrival instant.
    Priced {
        /// The history entry the instant resolved to.
        card_seq: HistorySeq,
    },
    /// No entry of the pinned snapshot covers the instant. The fee-only 1.5.5 posture, never a
    /// refusal at the door.
    NoCardInForce {
        /// The instant that fell in the hole.
        at: u64,
    },
    /// The entry in force does not price the node's currency. Never converted from another.
    CurrencyNotPriced {
        /// The entry that was in force.
        card_seq: HistorySeq,
        /// The currency the node reasons in.
        currency: CurrencyCode,
    },
}

/// A sized hold: the reservation in nano-units, and the posture that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HoldSize {
    nanos: u64,
    posture: HoldPosture,
}

impl HoldSize {
    /// The reservation, in nano-units.
    pub fn nanos(&self) -> u64 {
        self.nanos
    }

    /// Which card sized it, or why none did.
    pub fn posture(&self) -> HoldPosture {
        self.posture
    }

    /// The entry the sizing resolved to, when one did.
    pub fn card_seq(&self) -> Option<HistorySeq> {
        match self.posture {
            HoldPosture::Priced { card_seq } => Some(card_seq),
            _ => None,
        }
    }
}
