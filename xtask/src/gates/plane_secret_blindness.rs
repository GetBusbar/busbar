//! `cargo xtask gate plane-secret-blindness` — A PLANE NEVER RECEIVES SECRET BYTES.
//!
//! THE RULE (`docs/design/BUSBAR-1.6.0.md` THE DESIGN, the trust boundary, trust boundary): *"the kernel resolves
//! and audits secret material and delivers it only to the auth object bound to it and to the
//! non-plane plugin whose settings reference it … A plane never receives secret bytes."* The
//! kernel resolves every secret through the secret kind table (`SecretAxis`/`SecretCalls`); a
//! plane crate that names a secret resolver is a plane that can turn a reference into bytes.
//!
//! One row: no plane crate's production source names a secret-resolving surface
//! ([`NEEDLES`]). The sites the tree still carries are the drain-only ledger
//! `qa/plane-secret-blindness.toml` — each OWED to the slot that gives it a host-held replacement:
//! a2a's and voice's provider credentials to the auth styles (step 21), mcp's token-exchange
//! subject token to the auth styles, and the mcp stdio child's environment to the stdio transport.
//! A new site is RED; a drained site must be struck in the same commit.

use crate::ctx::{Ctx, Overlay};
use crate::gates::one_abi::{self, Finding, Spec};
use crate::gates::{Gate, Report};
use crate::ledger::Verdict;

pub const ROW_NAMES: &str = "plane-secret-blindness:names-a-resolver";

/// The secret-resolving surfaces, as whole words.
pub const NEEDLES: &[&str] = &[
    "SecretResolve",
    "SecretResolver",
    "secret_resolver",
    "SecretCalls",
    "SecretAxis",
    "resolve_linked_string",
    "resolve_builtin",
    "resolve_builtin_string",
];

/// The crates that still carry plane code beside the `busbar-plane-*` crates.
/// `busbar-voice` is struck: FLIP-STREAMING deleted the legacy streams crate.
pub const PLANE_HOMES: &[&str] = &["busbar-llm", "busbar-mcp", "busbar-a2a"];

pub const SPEC: Spec = Spec {
    gate: "plane-secret-blindness",
    ledger: "qa/plane-secret-blindness.toml",
    rules: &[(
        ROW_NAMES,
        "no plane crate names a secret-resolving surface (THE DESIGN, the trust boundary)",
    )],
    header: "# plane-secret-blindness: DRAIN-ONLY ledger (THE DESIGN, the trust boundary: a plane never receives secret\n\
             # bytes). Each row is a plane site that still resolves a secret reference, OWED to the slot\n\
             # that gives it a host-held replacement: a2a/voice provider credentials and the mcp\n\
             # token-exchange subject token to the auth styles (step 21); the mcp stdio child's\n\
             # environment to the stdio transport (CONNECTOR). Strike a row in the commit that drains\n\
             # it; never add one. Regenerate with `cargo xtask gate plane-secret-blindness --write`.\n",
};

fn is_plane(name: &str) -> bool {
    name.starts_with("busbar-plane-") || PLANE_HOMES.contains(&name)
}

pub fn scan(cx: &Ctx) -> (Vec<Finding>, Vec<String>) {
    let mut findings = Vec::new();
    let mut errors = Vec::new();
    let members = match one_abi::members(cx) {
        Ok(m) => m,
        Err(e) => return (findings, vec![e]),
    };
    let planes: Vec<_> = members.iter().filter(|m| is_plane(&m.name)).collect();
    if planes.len() < PLANE_HOMES.len() {
        errors.push(format!(
            "the workspace read as {} plane crate(s); the scan has gone blind",
            planes.len()
        ));
    }
    for m in planes {
        let files = match one_abi::rs_files(cx, &m.dir) {
            Ok(f) => f,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };
        for f in &files {
            let rel = f.rel_str();
            if rel.contains("/testkit/") || rel.contains("/bin/") {
                continue;
            }
            for sl in one_abi::production(&f.text) {
                for n in NEEDLES {
                    if one_abi::has_word(&sl.counted, n) {
                        findings.push(Finding::new(ROW_NAMES, &rel, *n, sl.no));
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
        let mut prose = Overlay::new();
        prose.set(
            file,
            "// a plane never names SecretResolve\npub const NOTE: &str = \"secret_resolver\";\n",
        );
        let mut report = one_abi::selftest(
            cx,
            self,
            &SPEC,
            vec![(
                ROW_NAMES,
                "a plane crate naming a secret resolver is RED, naming it",
                plant,
                vec![file, "SecretResolve"],
            )],
        );
        report.push(crate::gates::prove_rows_green(
            cx,
            self,
            "a comment or a string literal naming a resolver is not a finding",
            &[ROW_NAMES],
            prose,
        ));
        report
    }
}
