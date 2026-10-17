//! `cargo xtask gate dialect-map` — EVERY COMMITTED DIALECT TABLE IS ITS MAPPING FILE, COMPILED.
//!
//! The LLM plane's dialects state their wire <> IR mapping by hand in
//! `crates/busbar-plane-llm/dialects/<d>.toml`, and `cargo xtask dialect compile`
//! ([`crate::dialect`]) emits the committed `src/codec/<d>/map.gen.rs` the plane compiles. A table
//! file edited by hand, or a mapping file edited without a recompile, is a plane that no longer runs
//! the mapping it states. The same compile renders the translation matrix
//! (`docs/llm-translation-matrix.md`), so a matrix edited by hand, or left stale beside an edited
//! mapping file, is the same drift. This gate compiles every mapping file afresh and is RED, naming
//! the file, when any committed output differs from (or is missing beside) its compile.

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

        // An ANSWER row naming a slot the registry (`codec::carry::AnswerSlot`) does not have.
        let anthropic = format!("{}/anthropic.toml", crate::dialect::DIALECT_DIR);
        let mut unregistered = Overlay::new();
        unregistered.set(
            &anthropic,
            cx.read(&anthropic).unwrap_or_default().replacen(
                "\"stop_reason\" = { prim = \"finish_reason\" }",
                "\"stop_reason\" = { ir = \"no_such_answer_slot\" }",
                1,
            ),
        );
        report.push(prove_red(
            cx,
            self,
            "an answer row naming an unregistered slot does not compile, naming it",
            &[ROW_DRIFT],
            unregistered,
            &["no_such_answer_slot"],
        ));

        // A ROW KEY WRITTEN TWICE in one table (invalid TOML the line reader would otherwise take
        // as two rows). The second row is valid on its own, so only the repeat can refuse it.
        let mut twice = Overlay::new();
        twice.set(
            &anthropic,
            cx.read(&anthropic).unwrap_or_default().replacen(
                "\"stop_reason\" = { prim = \"finish_reason\" }",
                "\"stop_reason\" = { prim = \"finish_reason\" }\n\"stop_reason\" = { prim = \"finish_reason\" }",
                1,
            ),
        );
        report.push(prove_red(
            cx,
            self,
            "a row key written twice in one table does not compile, naming it",
            &[ROW_DRIFT],
            twice,
            &["\"stop_reason\" is written twice"],
        ));

        // A MAPPING FILE DELETED, the compile re-run (so the matrix is fresh), and its table file
        // left behind: the codec module still declares and compiles `cohere/map.gen.rs`, and no
        // instrument checks it any more (audit XA2 HIGH 1, XF HIGH 12).
        let cohere_source = format!("{}/cohere.toml", crate::dialect::DIALECT_DIR);
        let deleted_cx = cx.clone();
        report.push(prove_red(
            cx,
            self,
            "a deleted mapping file whose table file stays declared is RED, naming the dialect",
            &[ROW_DRIFT],
            move || {
                let mut ov = Overlay::new();
                ov.remove(&cohere_source);
                recompiled_matrix(&deleted_cx, ov)
            },
            &["cohere"],
        ));

        // ALL THREE GONE TOGETHER (mapping file, table file, the module's declaration of it), the
        // compile re-run: the roster still agrees with itself at five, under the floor of six.
        let codec_mod = "crates/busbar-plane-llm/src/codec/cohere/mod.rs";
        let gone_cx = cx.clone();
        let gone_mod = cx
            .read(codec_mod)
            .unwrap_or_default()
            .replace("#[path = \"map.gen.rs\"]", "");
        report.push(prove_red(
            cx,
            self,
            "a dialect roster under its floor of six is RED, naming the floor",
            &[ROW_DRIFT],
            move || {
                let mut ov = Overlay::new();
                ov.remove(format!("{}/cohere.toml", crate::dialect::DIALECT_DIR));
                ov.remove(crate::dialect::gen_path("cohere"));
                ov.set(codec_mod, gone_mod);
                recompiled_matrix(&gone_cx, ov)
            },
            &["floor"],
        ));

        // A HAND EDIT of the generated translation matrix.
        let matrix = crate::dialect::MATRIX;
        let mut matrix_edit = Overlay::new();
        matrix_edit.set(
            matrix,
            cx.read(matrix)
                .unwrap_or_default()
                .replacen(" | - |", " | yes |", 1),
        );
        report.push(prove_red(
            cx,
            self,
            "a hand-edited translation matrix is RED, naming it",
            &[ROW_DRIFT],
            matrix_edit,
            &[matrix],
        ));

        report
    }
}

/// `ov` with the translation matrix set to what `cargo xtask dialect compile` would write over it:
/// a plant that models "deleted, recompiled, committed" rather than a stale matrix.
fn recompiled_matrix(cx: &Ctx, mut ov: Overlay) -> Overlay {
    if let Ok(compiled) = crate::dialect::compile_all(&cx.with_overlay(ov.clone())) {
        if let Some(m) = compiled
            .into_iter()
            .find(|c| c.target == crate::dialect::MATRIX)
        {
            ov.set(crate::dialect::MATRIX, m.text);
        }
    }
    ov
}
