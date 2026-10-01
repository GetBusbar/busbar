//! `cargo xtask gate dialect-map` — EVERY COMMITTED DIALECT TABLE IS ITS MAPPING FILE, COMPILED.
//!
//! The LLM plane's dialects state their wire <> IR mapping by hand in
//! `crates/busbar-plane-llm/dialects/<d>.toml`, and `cargo xtask dialect compile`
//! ([`crate::dialect`]) emits the committed `src/codec/<d>/map.gen.rs` the plane compiles. A table
//! file edited by hand, or a mapping file edited without a recompile, is a plane that no longer runs
//! the mapping it states. This gate compiles every mapping file afresh and is RED, naming the file,
//! when any committed table file differs from (or is missing beside) its compile.

use crate::ctx::{Ctx, Overlay};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};

pub const ROW_DRIFT: &str = "dialect-map:drift";

pub struct DialectMapGate;

impl Gate for DialectMapGate {
    fn name(&self) -> &'static str {
        "dialect-map"
    }

    fn owed(&self) -> Vec<String> {
        vec![ROW_DRIFT.to_string()]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let row = match crate::dialect::compile_all(cx) {
            Err(why) => Row::fail(ROW_DRIFT, "a dialect mapping file does not compile", why),
            Ok(compiled) => {
                let drifted: Vec<String> = compiled
                    .iter()
                    .filter(|c| cx.read(&c.target).ok().as_deref() != Some(c.text.as_str()))
                    .map(|c| format!("{} (from {})", c.target, c.source))
                    .collect();
                if drifted.is_empty() {
                    Row::pass(
                        ROW_DRIFT,
                        "every committed dialect table equals its mapping file, compiled",
                        format!(
                            "{} mapping file(s) compiled; no table file differs",
                            compiled.len()
                        ),
                    )
                } else {
                    Row::fail(
                        ROW_DRIFT,
                        "a committed dialect table differs from its mapping file, compiled",
                        format!(
                            "{} — run `cargo xtask dialect compile` and commit the result; a \
                             table file is never edited by hand",
                            drifted.join(" | ")
                        ),
                    )
                }
            }
        };
        Verdict::of(vec![row])
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "every committed dialect table equals a fresh compile",
            &[ROW_DRIFT],
        ));

        // A HAND EDIT of a committed table file.
        let target = crate::dialect::gen_path("openai_chat");
        let mut edited = Overlay::new();
        edited.set(
            &target,
            cx.read(&target)
                .unwrap_or_default()
                .replace("Dir::Both", "Dir::Read"),
        );
        report.push(prove_red(
            cx,
            self,
            "a hand-edited table file is RED, naming it",
            &[ROW_DRIFT],
            edited,
            &[target.as_str()],
        ));

        // A MAPPING FILE edited without a recompile.
        let source = format!("{}/openai_responses.toml", crate::dialect::DIALECT_DIR);
        let mut stale = Overlay::new();
        stale.set(
            &source,
            cx.read(&source)
                .unwrap_or_default()
                .replace("\"verbosity\"", "\"tone\""),
        );
        let responses = crate::dialect::gen_path("openai_responses");
        report.push(prove_red(
            cx,
            self,
            "a mapping file edited without a recompile is RED, naming its table file",
            &[ROW_DRIFT],
            stale,
            &[responses.as_str()],
        ));

        report
    }
}
