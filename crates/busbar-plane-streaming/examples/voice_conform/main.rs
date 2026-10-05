// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE VOICE CONFORMANCE HARNESS — the driver behind `testing/voice-conformance/`, re-homed onto
//! the streaming plane's DOOR (ARCHITECT Q6: the streaming plane's conformance MUST-set, built
//! against `busbar-plane-streaming`, linked and dlopened, RED arm kept).
//!
//! A dev-only example: never shipped, no production dependency. Every assertion drives the door
//! through `busbar-plugin-loader` BOTH ways — the LINKED door (`busbar_plane_streaming::door::door`)
//! and the DROPPED door (the `streaming_door` example `cdylib`, dlopened) — and requires both to
//! answer identically, then judges the answer, then requires the leg's planted wrong answer to be
//! refused by the same judgment (`door::judge`). `VOICE_CONFORM_RED=1` makes the planted answers
//! the subject: every leg must then go RED.
//!
//! Output contract (the runner greps `^RESULT `): each assertion prints exactly one line
//!   RESULT <slice> <PASS|FAIL> <detail>
//! Non-`RESULT` lines (`SUBITEM`) are ignored by the runner.
//!
//! ```text
//! voice_conform spec <openai|gemini> <fixtures_dir>
//! voice_conform replay <fixtures_root>
//! voice_conform cross <oo|og|go|gg> <openai_dir> <gemini_dir> <map.json>
//! voice_conform governance <checkpoint>
//! voice_conform composition <slice>
//! ```

use std::path::Path;

mod codec_legs;
mod composition;
mod door;
mod governance;

fn usage() -> ! {
    eprintln!(
        "usage:\n  voice_conform spec <openai|gemini> <fixtures_dir>\n  voice_conform replay \
         <fixtures_root>\n  voice_conform cross <oo|og|go|gg> <openai_dir> <gemini_dir> \
         <map.json>\n  voice_conform governance <checkpoint>\n  voice_conform composition <slice>"
    );
    std::process::exit(2);
}

/// Argument `i`, or the usage and exit 2.
fn nth(args: &[String], i: usize) -> &str {
    match args.get(i) {
        Some(a) => a.as_str(),
        None => usage(),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rig = door::Rig::boot();
    let code = match nth(&args, 1) {
        "spec" => codec_legs::spec(&rig, nth(&args, 2), Path::new(nth(&args, 3))),
        "replay" => codec_legs::replay(&rig, Path::new(nth(&args, 2))),
        "cross" => {
            let map: serde_json::Value = match std::fs::read(nth(&args, 5))
                .map_err(|e| e.to_string())
                .and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
            {
                Ok(map) => map,
                Err(e) => {
                    door::result(
                        nth(&args, 2),
                        false,
                        "map",
                        &format!("{}: {e}", nth(&args, 5)),
                    );
                    std::process::exit(1);
                }
            };
            codec_legs::cross(
                &rig,
                nth(&args, 2),
                Path::new(nth(&args, 3)),
                Path::new(nth(&args, 4)),
                &map,
            )
        }
        "governance" => governance::run(&rig, nth(&args, 2)),
        "composition" => composition::run(&rig, nth(&args, 2)),
        _ => usage(),
    };
    std::process::exit(code);
}
