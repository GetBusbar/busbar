//! `cargo xtask gate plane-secret-blindness` — A PLANE NEVER RECEIVES SECRET BYTES.
//!
//! THE RULE (`docs/design/BUSBAR-1.6.0.md` THE DESIGN, the trust boundary, trust boundary): *"the kernel resolves
//! and audits secret material and delivers it only to the auth object bound to it and to the
//! non-plane plugin whose settings reference it … A plane never receives secret bytes."* The
//! kernel resolves every secret through the secret kind table (`SecretAxis`/`SecretCalls`); a
//! plane crate that names a secret resolver is a plane that can turn a reference into bytes, and a
//! plane crate that calls a resolved secret's accessor (`Secret::expose`, Part 2 #54: the one raw
//! accessor, sealed by a `KernelSeal`) is a plane that already holds them.
//!
//! Two rows over every plane-family crate the kind census names
//! ([`crate::gates::kind_isolation::plane_kind_src_roots`]: the `busbar-plane-*` crates and the
//! legacy engines, never a hand list): no production source names a secret-resolving surface
//! ([`NEEDLES`]), and none calls a secret-exposing accessor ([`EXPOSERS`]). Every forbidden name
//! must be DEFINED somewhere in the tree's production source, so a rename cannot silently empty
//! either list (an undefined name reds `:ledger`). The sites the tree still carries are the
//! drain-only ledger `qa/plane-secret-blindness.toml` — each OWED to the slot that gives it a
//! host-held replacement: a2a's and voice's provider credentials to the auth styles (step 21), and
//! the legacy engines' `Secret::expose` reads to their deletion (row 155). An exposure row is
//! COUNTED (`count = N`, one per line), so it only shrinks. A new site is RED; a drained site must
//! be struck (or its count lowered) in the same commit.

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::one_abi::{self, Finding, Spec};
use crate::gates::{Gate, Report};
use crate::ledger::Verdict;

pub const ROW_NAMES: &str = "plane-secret-blindness:names-a-resolver";
pub const ROW_EXPOSES: &str = "plane-secret-blindness:exposes-secret-bytes";

/// The secret-resolving surfaces, as whole words. Each must be defined in the tree
/// ([`undefined_names`]).
pub const NEEDLES: &[&str] = &[
    "SecretResolve",
    "SecretResolver",
    "secret_resolver",
    "SecretCalls",
    "SecretAxis",
    "SecretModule",
    "resolve_linked_string",
];

/// The accessors that hand their caller a RESOLVED secret's plaintext, as whole words (a call, a
/// path, a method reference): `busbar_contract::redacted::Secret::expose` is the one way to reach
/// the value inside a `Secret` (Part 2 #54), sealed by a `KernelSeal`. Each must be defined in the
/// tree ([`undefined_names`]).
pub const EXPOSERS: &[&str] = &["expose"];

pub const SPEC: Spec = Spec {
    gate: "plane-secret-blindness",
    ledger: "qa/plane-secret-blindness.toml",
    rules: &[
        (
            ROW_NAMES,
            "no plane crate names a secret-resolving surface (THE DESIGN, the trust boundary)",
        ),
        (
            ROW_EXPOSES,
            "no plane crate reads a resolved secret's bytes (THE DESIGN, the trust boundary)",
        ),
    ],
    header: "# plane-secret-blindness: DRAIN-ONLY ledger (THE DESIGN, the trust boundary: a plane never receives secret\n\
             # bytes). Each row is a plane site that still resolves a secret reference or reads a resolved\n\
             # secret's bytes, OWED to the slot that gives it a host-held replacement: a2a/voice provider\n\
             # credentials to the auth styles (step 21); the legacy engines' Secret::expose reads to their\n\
             # deletion (row 155). An exposes-secret-bytes row is COUNTED (`count = N`, one per line) and\n\
             # only goes down. Strike a row (or lower its count) in the commit that drains it; never add\n\
             # one. `cargo xtask gate plane-secret-blindness --write` regenerates the rows, each with\n\
             # its count; a row or a count above the base's ledger is refused.\n",
};

/// The plane-family crate directories (`crates/x`), from the kind census.
fn plane_dirs(cx: &Ctx) -> Result<Vec<String>, String> {
    Ok(crate::gates::kind_isolation::plane_kind_src_roots(cx)?
        .into_iter()
        .map(|root| root.strip_suffix("/src").unwrap_or(&root).to_string())
        .collect())
}

/// THE FORBIDDEN-NAME CENSUS: every name in `names` that no production line under `crates/*/src`
/// defines (`fn`, `struct`, `trait`, `enum`, `type`, or a `pub` field). A list that names an API the
/// tree no longer has polices nothing, so a rename must red here rather than empty the list.
pub fn undefined_names(cx: &Ctx, names: &[&str]) -> Result<Vec<String>, String> {
    let files = cx
        .walk(
            &WalkSpec::new(["crates"])
                .ext("rs")
                .exclude(["/tests/", "/benches/"])
                .min_files(1),
        )
        .map_err(|e| format!("crates: {e:?}"))?;
    // Each name with the spellings that define it, written once rather than once per line.
    let mut missing: Vec<(&str, Vec<String>)> = names
        .iter()
        .map(|n| {
            let mut defs: Vec<String> = ["fn", "struct", "trait", "enum", "type"]
                .iter()
                .map(|kw| format!("{kw} {n}"))
                .collect();
            defs.push(format!("pub {n}:"));
            (*n, defs)
        })
        .collect();
    for f in &files {
        if missing.is_empty() {
            break;
        }
        if !f.rel_str().contains("/src/") {
            continue;
        }
        // A file whose text holds none of the names still missing defines none of them: every
        // definition spelling carries the name verbatim, so the file is not lexed at all.
        if !missing.iter().any(|(n, _)| f.text.contains(n)) {
            continue;
        }
        for sl in one_abi::production(&f.text) {
            missing.retain(|(_, defs)| !defs.iter().any(|d| one_abi::has_word(&sl.counted, d)));
        }
    }
    Ok(missing.into_iter().map(|(n, _)| n.to_string()).collect())
}

pub fn scan(cx: &Ctx) -> (Vec<Finding>, Vec<String>) {
    let mut findings = Vec::new();
    let mut errors = Vec::new();
    let all: Vec<&str> = NEEDLES.iter().chain(EXPOSERS).copied().collect();
    match undefined_names(cx, &all) {
        Ok(gone) => {
            for n in gone {
                errors.push(format!(
                    "forbidden name `{n}` is defined nowhere in crates/*/src production source: the list names an API the tree no longer has (a rename emptied it); name the live API"
                ));
            }
        }
        Err(e) => errors.push(e),
    }
    let dirs = match plane_dirs(cx) {
        Ok(d) => d,
        Err(e) => {
            errors.push(e);
            return (findings, errors);
        }
    };
    for dir in dirs {
        let files = match one_abi::rs_files(cx, &dir) {
            Ok(f) => f,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };
        if files.is_empty() {
            errors.push(format!(
                "{dir}: a plane-family crate with ZERO .rs files under src/ is unscanned, not clean"
            ));
        }
        for f in &files {
            let rel = f.rel_str();
            if rel.contains("/testkit/") || rel.contains("/bin/") {
                continue;
            }
            for sl in one_abi::production(&f.text) {
                for (rule, list) in [(ROW_NAMES, NEEDLES), (ROW_EXPOSES, EXPOSERS)] {
                    for n in list {
                        if one_abi::has_word(&sl.counted, n) {
                            findings.push(Finding::new(rule, &rel, *n, sl.no));
                        }
                    }
                }
            }
        }
    }
    (findings, errors)
}

pub struct PlaneSecretBlindnessGate;

impl Gate for PlaneSecretBlindnessGate {
    fn name(&self) -> &'static str {
        SPEC.gate
    }

    fn owed(&self) -> Vec<String> {
        SPEC.owed()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let (findings, errors) = scan(cx);
        one_abi::verdict(cx, &SPEC, findings, errors)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let file = "crates/busbar-plane-llm/src/planted_secret.rs";
        let mut plant = Overlay::new();
        plant.set(
            file,
            "pub fn planted(r: &dyn busbar_contract::secret::SecretResolve) { let _ = r; }\n",
        );
        // RED (audit xtask H1 HIGH 1): a plane that reads a resolved secret's bytes through the live
        // accessor. The old needles were resolver names only, so this line matched none of them.
        let exposed = "crates/busbar-plane-llm/src/planted_exposure.rs";
        let mut exposure = Overlay::new();
        exposure.set(
            exposed,
            "pub fn planted(\n    k: &busbar_contract::redacted::Secret<String>,\n    s: &busbar_contract::plugin::TestKernelSeal,\n) -> usize {\n    k.expose(s).len()\n}\n",
        );
        let mut prose = Overlay::new();
        prose.set(
            file,
            "// a plane never names SecretResolve or calls expose\npub const NOTE: &str = \"secret_resolver Secret::expose\";\n",
        );
        let mut report = one_abi::selftest(
            cx,
            self,
            &SPEC,
            vec![
                (
                    ROW_NAMES,
                    "a plane crate naming a secret resolver is RED, naming it",
                    plant,
                    vec![file, "SecretResolve"],
                ),
                (
                    ROW_EXPOSES,
                    "a plane crate calling Secret::expose is RED, naming it",
                    exposure,
                    vec![exposed, "expose"],
                ),
            ],
        );
        report.push(crate::gates::prove_rows_green(
            cx,
            self,
            "a comment or a string literal naming a resolver or the accessor is not a finding",
            &[ROW_NAMES, ROW_EXPOSES],
            prose,
        ));

        // RED: a counted exposure row only shrinks. One more `expose` line in a file the
        // ledger already counts is over its count, though the (rule, file, item) key is on record.
        // The ledger's last counted rows drained with the retired engine crate (DEV-GREEN row 83),
        // so the counted row is planted with its file: one `expose` line counted, a second beside
        // it is over the count though the (rule, file, item) key is on record.
        let counted = "crates/busbar-plane-llm/src/zz_planted_counted.rs";
        let one =
            "pub fn planted_one(k: &busbar_contract::redacted::Secret<String>) -> usize {\n    \
                   k.expose(&busbar_kernel::seal::lend()).len()\n}\n";
        let more =
            "pub fn planted_more(k: &busbar_contract::redacted::Secret<String>) -> usize {\n    \
                    k.expose(&busbar_kernel::seal::lend()).len()\n}\n";
        let ledger = cx.read(SPEC.ledger).unwrap_or_default();
        let mut ov = Overlay::new();
        ov.set(counted, format!("{one}{more}"));
        ov.set(
            SPEC.ledger,
            format!(
                "{ledger}\n[[finding]]\nrule = \"{ROW_EXPOSES}\"\nfile = \"{counted}\"\nitem = \
                 \"expose\"\ncount = 1\n"
            ),
        );
        report.push(crate::gates::prove_rows_red(
            cx,
            self,
            "one more expose line in a file the ledger counts is RED: a counted row never grows",
            &[ROW_EXPOSES],
            ov,
            &[counted, "over its counted row"],
        ));

        // RED: the forbidden-name census. Rename the accessor at its home and the list would name
        // an API the tree no longer has; the old gate never asked, so a rename emptied it silently.
        let home = "crates/busbar-contract/src/redacted.rs";
        if let Ok(text) = cx.read(home) {
            let mut ov = Overlay::new();
            ov.set(home, text.replace("fn expose<", "fn expose_renamed<"));
            let ledger_row = SPEC.ledger_row();
            report.push(crate::gates::prove_rows_red(
                &crate::gates::construction::ceilings::with_head_pin(cx),
                self,
                "a forbidden name defined nowhere in the tree is RED, naming it",
                &[ledger_row.as_str()],
                ov,
                &["`expose` is defined nowhere"],
            ));
        }
        report
    }
}
