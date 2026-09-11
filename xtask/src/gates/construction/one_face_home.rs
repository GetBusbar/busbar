//! `one-face-home` — the drain schedule of `docs/design/1.6.0-one-face-per-kind.md` §2, as a gate.
//!
//! Two claims over one measurement, because they are the two ways the ONE-FACE-HOME-PER-KIND shape
//! is broken:
//!
//! * **a contract KIND trait with zero implementors in the workspace** — `busbar_contract::kinds`
//!   names a trait core, the root and the units call, and if nothing implements it the kind's real
//!   face is somewhere else and `docs/design/PLUGIN-TREE.md` §1 is false for that row;
//! * **a plugin implementing a kind's WIRE face outside its one home** — an `impl <face> for` in a
//!   plugin crate naming a trait that lives anywhere but `busbar-contract`.
//!
//! This is deliberately NOT an extension of `kind-isolation:faces`
//! ([`crate::gates::kind_isolation::ROW_FACES`]): that rule reads the CRATE axis (is this crate
//! implementing another KIND's entry face — the question a crate's own naming answers wrong), this
//! one reads the FACE axis (does a face live where the design says one home should be). They share
//! no input and print no line the other could print.
//!
//! PINNED RED-FIRST at its measured count, exactly like `plane-no-money`/`hold-escapes`: a ratchet
//! that only falls, not a ceiling asserted at zero. §2's table of
//! `docs/design/1.6.0-one-face-per-kind.md` is the drain schedule — STORE-4b, secret, and auth each
//! drain part of the count as they land a kind's wire face onto `busbar-contract` (and give the kind
//! face its loader adapter); egress-auth drains it too, but the row it leaves standing never reaches
//! zero on its own terms (no plugin of that kind exists yet to have a face at all).
//!
//! Claim A's search is anchored to the QUALIFIED spelling (`kinds::<Trait>`) rather than the bare
//! trait name, on purpose: `Store` is also the name of the WIRE face a plugin implements, and a
//! bare-name search would count `impl Store for RamStore` (a wire-face impl, unrelated) as if it
//! answered the kind face, silently hiding the exact finding this claim exists to report.
//!
//! Claim B is scoped to a fixed, reviewed list of plugin-kind crate directories rather than a
//! tree-wide search, for the same reason kernel-seal-impls scopes to `allowed_root`: the loader's
//! own adapter implementations (`plugin_loader::{DynAuth, DynSecret, DynStore}`) are the
//! TRANSLATION this shape keeps, not a plugin, and the tooling crate's own default/example modules
//! are not a kind instance either — counting either would inflate the finding with sites the plan
//! does not move.

use crate::gates::construction::model::{need_int, plain, CRow, Cfg};
use crate::gates::construction::tree::Tree;
use crate::rx::Regex;

pub fn one_face_home(tree: &Tree, cfg: &Cfg) -> Result<Vec<CRow>, String> {
    let c = cfg.rule("one-face-home")?;
    let max_findings = need_int(c, "max_findings", "one-face-home")?;
    let kind_traits = c.list_of("kind_traits");
    let foreign_face_traits = c.list_of("foreign_face_traits");
    let foreign_face_crates = c.list_of("foreign_face_crates");

    let mut offenders: Vec<String> = Vec::new();

    // Claim A: a contract KIND trait (`busbar_contract::kinds::<Trait>`) with zero production
    // implementors anywhere in the workspace, matched only against the module-qualified spelling.
    for t in &kind_traits {
        let pat = Regex::new(&format!(r"impl(<[^>]*>)?\s+kinds::{t}\s+for"))?;
        let hits = tree.grep(&pat, true, None);
        if hits.is_empty() {
            offenders.push(format!(
                "zero-implementor\tbusbar_contract::kinds::{t}\tno production `impl kinds::{t} \
                 for` anywhere in the workspace: the kind face core, the root and the units name \
                 has no implementor, so a reader of `kinds::{t}` cannot tell what really answers \
                 it. See docs/design/1.6.0-one-face-per-kind.md §2's row for `{t}`'s drain step."
            ));
        }
    }

    // Claim B: a plugin implementing a still-foreign-homed WIRE face — a trait named in
    // `foreign_face_traits` (today: the busbar-api blocks secret/auth/store have not yet drained),
    // found in one of the reviewed plugin-kind crate directories.
    if !foreign_face_traits.is_empty() {
        let alt = foreign_face_traits.join("|");
        let pat = Regex::new(&format!(
            r"^impl(<[^>]*>)?\s+(\w+::)*({alt})(<[^>]*>)?\s+for"
        ))?;
        for krate in &foreign_face_crates {
            let files: Vec<String> = tree.crate_files(krate);
            for (rel, l) in tree.grep(&pat, true, Some(&files)) {
                offenders.push(format!(
                    "foreign-home\t{rel}:{}\t{krate} implements a wire face outside \
                     busbar-contract: `{}`. The one home for a kind's wire face is the crate a \
                     plugin manifest may name; this trait's definition has not moved there yet — \
                     see docs/design/1.6.0-one-face-per-kind.md §2/§3 for which ordered-plan step \
                     drains it.",
                    l.no,
                    l.code.trim(),
                ));
            }
        }
    }

    offenders.sort();
    let current = offenders.len() as i64;
    let detail = if offenders.is_empty() {
        format!(
            "0 finding(s) over {} kind trait(s) and {} foreign-face crate(s)",
            kind_traits.len(),
            foreign_face_crates.len()
        )
    } else {
        format!(
            "{current} finding(s) (ceiling {max_findings}): {}",
            offenders.join(" | ")
        )
    };
    Ok(vec![plain(
        "one-face-home",
        current <= max_findings,
        "a contract kind trait has an implementor and no plugin implements a face outside its one \
         home",
        detail,
        current,
        max_findings,
        offenders,
    )])
}
