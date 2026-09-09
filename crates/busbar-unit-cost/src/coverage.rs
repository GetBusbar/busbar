//! UNPRICED CLASS = BOOT REFUSAL (ruling 5).
//!
//! A plane declares the classes it reports. A rate table carries rows for the cells somebody has
//! priced. This module is the one question between them: **is there a class an enabled plane reports
//! that has no rate row on one of its lanes?** If there is, the deployment would meter a quantity
//! and bill it at nothing, and the operator would never be told -- the invoice is simply short by
//! whatever that class was worth. Ruling 5 refuses to start rather than serve that.
//!
//! **FREE IS AN EXPLICIT ZERO ROW.** The rule reads [`RateTable::prices_cell`], which asks whether a
//! row EXISTS, not what it says. A row pricing a class at zero satisfies the rule completely: the
//! operator has stated that the class is free and the table can show you they stated it. What the
//! rule refuses is silence. That distinction is the whole point, and it is why the table keeps
//! `None` and `Some(0)` apart.
//!
//! **A DEPLOYMENT THAT PRICES NOTHING IS NOT A DEPLOYMENT WITH UNPRICED CLASSES.** Where the table
//! carries no rows at all, [`unpriced_cells`] finds nothing. A `rate_card:`-less config has not said
//! its traffic is free and has not said it is unpriced -- it has not opted into pricing at all,
//! which is what every release before this one meant by omitting the section, and refusing it now
//! would refuse every config that has ever booted without a card. The rule bites once an operator
//! has started pricing: from then on, pricing SOME of what a plane reports and not the rest is the
//! error, because that is the case where a number an operator believes is a bill is quietly wrong.
//!
//! **A ROW ANYWHERE ON THE CELL COUNTS, INCLUDING A FUTURE ONE.** The question is whether a price
//! has been stated, not whether one is in force at this instant. A row that starts next month is a
//! decision the operator has made and written down; refusing a config for planning ahead would
//! refuse the thing add-only dated rows exist to allow.

use crate::currency::CurrencyCode;
use crate::table::RateTable;

/// One enabled plane and the classes it reports, as data.
///
/// The classes are plain strings, which is what lets this rule run over a plane it cannot name: the
/// caller reads them off the plane's own declaration and hands them across. Nothing here knows a
/// class by name, which is ruling 4's "the cost unit knows no class by name" held to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaneClasses<'a> {
    /// The plane's registry key, for the refusal to name.
    pub plane: &'a str,
    /// Every class this plane reports, in the config/wire spelling.
    pub classes: &'a [&'a str],
}

/// One `(plane, lane, class)` the deployment would meter and could not price.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnpricedCell {
    /// The plane that reports the class.
    pub plane: String,
    /// The lane it would be reported on.
    pub lane: String,
    /// The class nobody has priced.
    pub class: String,
}

/// EVERY CELL AN ENABLED PLANE WOULD METER AND THE TABLE CANNOT PRICE.
///
/// The cross product of the planes' declared classes and the lanes they may be served on, minus
/// every cell the table carries a row for. Sorted and deduplicated, so a refusal built from it reads
/// the same way on every boot of the same config -- a diagnostic whose line order moved between runs
/// would be a diagnostic nobody could diff.
///
/// Empty when the table itself is empty: see the module note. Empty is the boot-passes answer.
#[must_use]
pub fn unpriced_cells(
    table: &RateTable,
    planes: &[PlaneClasses<'_>],
    lanes: &[&str],
    currency: CurrencyCode,
) -> Vec<UnpricedCell> {
    if table.is_empty() {
        return Vec::new();
    }
    let mut found: Vec<UnpricedCell> = Vec::new();
    for plane in planes {
        for lane in lanes {
            for class in plane.classes {
                if !table.prices_cell(lane, class, currency) {
                    found.push(UnpricedCell {
                        plane: plane.plane.to_string(),
                        lane: (*lane).to_string(),
                        class: (*class).to_string(),
                    });
                }
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

/// THE REFUSAL AN OPERATOR READS, built from what [`unpriced_cells`] found.
///
/// It names every plane, lane and class it refused for -- not the first one -- because an operator
/// who fixes one and reboots into the next has been made to discover their config one restart at a
/// time. Each line is a cell, and the remedy is stated once at the end in the grammar the operator
/// would type, including the zero row that means free: the point of the refusal is that they choose,
/// not that they guess which of the two we wanted.
///
/// `None` when nothing was found, so the caller has one thing to test rather than two.
#[must_use]
pub fn refusal(unpriced: &[UnpricedCell]) -> Option<String> {
    if unpriced.is_empty() {
        return None;
    }
    let mut msg = format!(
        "rate_card is present but {} (plane, lane, class) cell{} no rate row, and an enabled plane \
         reports {} class{}: a metered quantity with no row is billed at nothing and no invoice \
         says so. Every class an enabled plane reports must be priced on every lane it is served \
         on; FREE IS AN EXPLICIT ZERO ROW.\n",
        unpriced.len(),
        if unpriced.len() == 1 {
            " has"
        } else {
            "s have"
        },
        if unpriced.len() == 1 { "that" } else { "those" },
        if unpriced.len() == 1 { "" } else { "es" },
    );
    for cell in unpriced {
        msg.push_str(&format!(
            "  - plane `{}` reports class `{}` on lane `{}`, which has no rate row\n",
            cell.plane, cell.class, cell.lane
        ));
    }
    msg.push_str(
        "\nPrice each one under rate_card (micro-units per unit), or state that it is free with an \
         explicit zero.",
    );
    Some(msg)
}
