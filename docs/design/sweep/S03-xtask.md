# S03-xtask — sweep verdicts

Slice: `xtask/` — THE GATE HARNESS ITSELF. 164 files, one verdict line each, in slice order.
X-id block: X-1200 .. X-1299. Read-and-report only; nothing in this slice was edited.

**The question asked of every gate row:** *what input makes this red, and can that input exist in
this tree?* A gate whose scan root, crate name, predicate or ref can no longer be satisfied is
blind and green, and that is the defect this slice exists to find.

Two rows are carried from other agents' verification and were re-verified here before being
written down; one finding (`reachability.rs`) was already on THE-LIST as **X-63** and is cited
rather than re-raised.

| FILE | VERDICT | EVIDENCE | ROWS |
|---|---|---|---|
| `xtask/Cargo.toml` | CLEAN | grep -n '"xtask"' Cargo.toml -> workspace member; `grep -n "^serde_json\\|^proc-macro2\\|^syn" Cargo.toml` -> :261,:251,:281 — all three `workspace = true` deps resolve | - |
| `xtask/fixtures/clean-pure/Cargo.toml` | CLEAN | grep -n '"clean-pure"' xtask/src/selftest.rs -> :139, driving denylist::run_on; expects 0 hits; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/clean-pure/src/lib.rs` | CLEAN | grep -n '"clean-pure"' xtask/src/selftest.rs -> :139, driving denylist::run_on; expects 0 hits; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/dirty-dep-hyphenated/async-std/Cargo.toml` | CLEAN | grep -n '"dirty-dep-hyphenated"' xtask/src/selftest.rs -> :153, expects `async-std`+`hyper-util`; both still banned (qa/construction.toml:1031, denylist.rs:90); `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/dirty-dep-hyphenated/async-std/src/lib.rs` | CLEAN | grep -n '"dirty-dep-hyphenated"' xtask/src/selftest.rs -> :153, expects `async-std`+`hyper-util`; both still banned (qa/construction.toml:1031, denylist.rs:90); `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/dirty-dep-hyphenated/Cargo.toml` | CLEAN | grep -n '"dirty-dep-hyphenated"' xtask/src/selftest.rs -> :153, expects `async-std`+`hyper-util`; both still banned (qa/construction.toml:1031, denylist.rs:90); `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/dirty-dep-hyphenated/hyper-util/Cargo.toml` | CLEAN | grep -n '"dirty-dep-hyphenated"' xtask/src/selftest.rs -> :153, expects `async-std`+`hyper-util`; both still banned (qa/construction.toml:1031, denylist.rs:90); `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/dirty-dep-hyphenated/hyper-util/src/lib.rs` | CLEAN | grep -n '"dirty-dep-hyphenated"' xtask/src/selftest.rs -> :153, expects `async-std`+`hyper-util`; both still banned (qa/construction.toml:1031, denylist.rs:90); `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/dirty-dep-hyphenated/src/lib.rs` | CLEAN | grep -n '"dirty-dep-hyphenated"' xtask/src/selftest.rs -> :153, expects `async-std`+`hyper-util`; both still banned (qa/construction.toml:1031, denylist.rs:90); `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/dirty-dep/Cargo.toml` | CLEAN | grep -n '"dirty-dep"' xtask/src/selftest.rs -> :146, expects offender `libc`; grep -n libc qa/construction.toml -> :1031 still bans it; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/dirty-dep/src/lib.rs` | CLEAN | grep -n '"dirty-dep"' xtask/src/selftest.rs -> :146, expects offender `libc`; grep -n libc qa/construction.toml -> :1031 still bans it; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/dirty-plane/Cargo.toml` | CLEAN | git grep -n "xtask/fixtures/dirty-plane" xtask/src -> gates/denylist_gate.rs:234; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/dirty-plane/crates/busbar-plane-demo/Cargo.toml` | CLEAN | git grep -n "xtask/fixtures/dirty-plane" xtask/src -> gates/denylist_gate.rs:234; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/dirty-plane/crates/busbar-plane-demo/src/lib.rs` | CLEAN | git grep -n "xtask/fixtures/dirty-plane" xtask/src -> gates/denylist_gate.rs:234; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/dirty-src/Cargo.toml` | CLEAN | grep -n '"dirty-src"' xtask/src/selftest.rs -> :160,:207; std::fs banned at qa/construction.toml:1029; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/dirty-src/src/lib.rs` | CLEAN | grep -n '"dirty-src"' xtask/src/selftest.rs -> :160,:207; std::fs banned at qa/construction.toml:1029; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/instance-noun/crates/busbar-core/src/lib.rs` | CLEAN | grep -n "xtask/fixtures/instance-noun" xtask/src/gates/instance_noun_neutrality.rs -> :699 FIX, one RED case per noun; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/instance-noun/crates/busbar-mcp/src/lib.rs` | CLEAN | grep -n "xtask/fixtures/instance-noun" xtask/src/gates/instance_noun_neutrality.rs -> :699 FIX, one RED case per noun; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/no-crates-dir/Cargo.toml` | CLEAN | grep -n '"no-crates-dir"' xtask/src/selftest.rs -> :407 ("vacuous config: no crates/ directory"); `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/no-crates-dir/src/lib.rs` | CLEAN | grep -n '"no-crates-dir"' xtask/src/selftest.rs -> :407 ("vacuous config: no crates/ directory"); `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/optional-dep-active/Cargo.toml` | CLEAN | grep -n '"optional-dep-active"' xtask/src/selftest.rs -> :177, expects RED on an ACTIVE optional edge; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/optional-dep-active/mid/Cargo.toml` | CLEAN | grep -n '"optional-dep-active"' xtask/src/selftest.rs -> :177, expects RED on an ACTIVE optional edge; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/optional-dep-active/mid/src/lib.rs` | CLEAN | grep -n '"optional-dep-active"' xtask/src/selftest.rs -> :177, expects RED on an ACTIVE optional edge; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/optional-dep-active/src/lib.rs` | CLEAN | grep -n '"optional-dep-active"' xtask/src/selftest.rs -> :177, expects RED on an ACTIVE optional edge; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/optional-dep-inactive/Cargo.toml` | CLEAN | grep -n '"optional-dep-inactive"' xtask/src/selftest.rs -> :170, expects GREEN on a phantom edge; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/optional-dep-inactive/mid/Cargo.toml` | CLEAN | grep -n '"optional-dep-inactive"' xtask/src/selftest.rs -> :170, expects GREEN on a phantom edge; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/optional-dep-inactive/mid/src/lib.rs` | CLEAN | grep -n '"optional-dep-inactive"' xtask/src/selftest.rs -> :170, expects GREEN on a phantom edge; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/optional-dep-inactive/src/lib.rs` | CLEAN | grep -n '"optional-dep-inactive"' xtask/src/selftest.rs -> :170, expects GREEN on a phantom edge; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/plane-money/crates/busbar-kernel/src/lib.rs` | CLEAN | git grep -n "xtask/fixtures/plane-money" xtask/src -> gates/plane_pricing_blindness.rs:1120; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/plane-money/crates/busbar-llm/src/unit/mod.rs` | CLEAN | git grep -n "xtask/fixtures/plane-money" xtask/src -> gates/plane_pricing_blindness.rs:1120; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/plane-money/crates/busbar-llm/src/unit/money.rs` | CLEAN | git grep -n "xtask/fixtures/plane-money" xtask/src -> gates/plane_pricing_blindness.rs:1120; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/plane-money/crates/busbar-llm/src/unit/oracle_double.rs` | CLEAN | git grep -n "xtask/fixtures/plane-money" xtask/src -> gates/plane_pricing_blindness.rs:1120; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/plane-money/crates/busbar-plane-llm/src/meta.rs` | CLEAN | git grep -n "xtask/fixtures/plane-money" xtask/src -> gates/plane_pricing_blindness.rs:1120; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/plane-money/crates/busbar-plane-llm/src/plane.rs` | CLEAN | git grep -n "xtask/fixtures/plane-money" xtask/src -> gates/plane_pricing_blindness.rs:1120; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/plane-root-missing/crates/busbar-neutral-demo/src/lib.rs` | CLEAN | grep -n PLANE_ROOT_MISSING_FIXTURE xtask/src/gates/mod.rs -> :2243; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability-empty/crates/busbar/Cargo.toml` | CLEAN | grep -n "const FIX_EMPTY" xtask/src/gates/reachability.rs -> :1568; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability-empty/crates/busbar/src/other.rs` | CLEAN | grep -n "const FIX_EMPTY" xtask/src/gates/reachability.rs -> :1568; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability-green/crates/busbar/Cargo.toml` | CLEAN | grep -n "const FIX_GREEN" xtask/src/gates/reachability.rs -> :1567; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability-green/crates/busbar/src/main.rs` | CLEAN | grep -n "const FIX_GREEN" xtask/src/gates/reachability.rs -> :1567; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability-green/crates/busbar/src/root/mod.rs` | CLEAN | grep -n "const FIX_GREEN" xtask/src/gates/reachability.rs -> :1567; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability-green/crates/busbar/src/root/registry.rs` | CLEAN | grep -n "const FIX_GREEN" xtask/src/gates/reachability.rs -> :1567; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability-green/crates/busbar/src/root/tests/units_a2a.rs` | CLEAN | grep -n "const FIX_GREEN" xtask/src/gates/reachability.rs -> :1567; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability-green/crates/busbar/src/root/tests/units_decision.rs` | CLEAN | grep -n "const FIX_GREEN" xtask/src/gates/reachability.rs -> :1567; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability-green/crates/busbar/src/root/tests/units_llm.rs` | CLEAN | grep -n "const FIX_GREEN" xtask/src/gates/reachability.rs -> :1567; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability-green/crates/busbar/src/root/tests/units_mcp.rs` | CLEAN | grep -n "const FIX_GREEN" xtask/src/gates/reachability.rs -> :1567; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability-green/crates/busbar/src/root/tests/units_voice.rs` | CLEAN | grep -n "const FIX_GREEN" xtask/src/gates/reachability.rs -> :1567; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability-green/crates/busbar/src/root/units_a2a.rs` | CLEAN | grep -n "const FIX_GREEN" xtask/src/gates/reachability.rs -> :1567; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability-green/crates/busbar/src/root/units_decision.rs` | CLEAN | grep -n "const FIX_GREEN" xtask/src/gates/reachability.rs -> :1567; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability-green/crates/busbar/src/root/units_llm.rs` | CLEAN | grep -n "const FIX_GREEN" xtask/src/gates/reachability.rs -> :1567; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability-green/crates/busbar/src/root/units_mcp.rs` | CLEAN | grep -n "const FIX_GREEN" xtask/src/gates/reachability.rs -> :1567; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability-green/crates/busbar/src/root/units_voice.rs` | CLEAN | grep -n "const FIX_GREEN" xtask/src/gates/reachability.rs -> :1567; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability-lib/crates/busbar/Cargo.toml` | CLEAN | grep -n "const FIX_LIB" xtask/src/gates/reachability.rs -> :1569; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability-lib/crates/busbar/src/lib.rs` | CLEAN | grep -n "const FIX_LIB" xtask/src/gates/reachability.rs -> :1569; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability-lib/crates/busbar/src/main.rs` | CLEAN | grep -n "const FIX_LIB" xtask/src/gates/reachability.rs -> :1569; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability-lib/crates/busbar/src/root/mod.rs` | CLEAN | grep -n "const FIX_LIB" xtask/src/gates/reachability.rs -> :1569; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability-lib/crates/busbar/src/root/registry.rs` | CLEAN | grep -n "const FIX_LIB" xtask/src/gates/reachability.rs -> :1569; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability/crates/busbar/Cargo.toml` | CLEAN | grep -n "const FIX_RED" xtask/src/gates/reachability.rs -> :1566; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability/crates/busbar/src/main.rs` | CLEAN | grep -n "const FIX_RED" xtask/src/gates/reachability.rs -> :1566; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability/crates/busbar/src/root/mod.rs` | CLEAN | grep -n "const FIX_RED" xtask/src/gates/reachability.rs -> :1566; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability/crates/busbar/src/root/money_book.rs` | CLEAN | grep -n "const FIX_RED" xtask/src/gates/reachability.rs -> :1566; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability/crates/busbar/src/root/registry.rs` | CLEAN | grep -n "const FIX_RED" xtask/src/gates/reachability.rs -> :1566; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability/crates/busbar/src/root/tests/units_a2a.rs` | CLEAN | grep -n "const FIX_RED" xtask/src/gates/reachability.rs -> :1566; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability/crates/busbar/src/root/tests/units_decision.rs` | CLEAN | grep -n "const FIX_RED" xtask/src/gates/reachability.rs -> :1566; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability/crates/busbar/src/root/tests/units_llm.rs` | CLEAN | grep -n "const FIX_RED" xtask/src/gates/reachability.rs -> :1566; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability/crates/busbar/src/root/tests/units_mcp.rs` | CLEAN | grep -n "const FIX_RED" xtask/src/gates/reachability.rs -> :1566; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability/crates/busbar/src/root/tests/units_voice.rs` | CLEAN | grep -n "const FIX_RED" xtask/src/gates/reachability.rs -> :1566; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability/crates/busbar/src/root/units_a2a.rs` | CLEAN | grep -n "const FIX_RED" xtask/src/gates/reachability.rs -> :1566; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability/crates/busbar/src/root/units_decision.rs` | CLEAN | grep -n "const FIX_RED" xtask/src/gates/reachability.rs -> :1566; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability/crates/busbar/src/root/units_llm.rs` | CLEAN | grep -n "const FIX_RED" xtask/src/gates/reachability.rs -> :1566; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability/crates/busbar/src/root/units_mcp.rs` | CLEAN | grep -n "const FIX_RED" xtask/src/gates/reachability.rs -> :1566; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability/crates/busbar/src/root/units_orphan.rs` | CLEAN | grep -n "const FIX_RED" xtask/src/gates/reachability.rs -> :1566; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/reachability/crates/busbar/src/root/units_voice.rs` | CLEAN | grep -n "const FIX_RED" xtask/src/gates/reachability.rs -> :1566; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/renamed-rule-table/Cargo.toml` | CLEAN | grep -n '"renamed-rule-table"' xtask/src/selftest.rs -> :405; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/renamed-rule-table/crates/busbar-plane-demo/Cargo.toml` | CLEAN | grep -n '"renamed-rule-table"' xtask/src/selftest.rs -> :405; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/renamed-rule-table/crates/busbar-plane-demo/src/lib.rs` | CLEAN | grep -n '"renamed-rule-table"' xtask/src/selftest.rs -> :405; `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/via-bypass/Cargo.toml` | CLEAN | grep -n '"via-bypass"' xtask/src/selftest.rs -> :289,:520 (waiver must STAY red); `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/via-bypass/mid/Cargo.toml` | CLEAN | grep -n '"via-bypass"' xtask/src/selftest.rs -> :289,:520 (waiver must STAY red); `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/via-bypass/mid/src/lib.rs` | CLEAN | grep -n '"via-bypass"' xtask/src/selftest.rs -> :289,:520 (waiver must STAY red); `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/via-bypass/src/lib.rs` | CLEAN | grep -n '"via-bypass"' xtask/src/selftest.rs -> :289,:520 (waiver must STAY red); `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/via-multi/Cargo.toml` | CLEAN | grep -n '"via-multi"' xtask/src/selftest.rs -> :333 (comma-separated `via` list); `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/via-multi/mid-a/Cargo.toml` | CLEAN | grep -n '"via-multi"' xtask/src/selftest.rs -> :333 (comma-separated `via` list); `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/via-multi/mid-a/src/lib.rs` | CLEAN | grep -n '"via-multi"' xtask/src/selftest.rs -> :333 (comma-separated `via` list); `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/via-multi/mid-b/Cargo.toml` | CLEAN | grep -n '"via-multi"' xtask/src/selftest.rs -> :333 (comma-separated `via` list); `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/via-multi/mid-b/src/lib.rs` | CLEAN | grep -n '"via-multi"' xtask/src/selftest.rs -> :333 (comma-separated `via` list); `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/via-multi/src/lib.rs` | CLEAN | grep -n '"via-multi"' xtask/src/selftest.rs -> :333 (comma-separated `via` list); `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/via-only/Cargo.toml` | CLEAN | grep -n '"via-only"' xtask/src/selftest.rs -> :233,:519 (`via` fully covers); `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/via-only/mid/Cargo.toml` | CLEAN | grep -n '"via-only"' xtask/src/selftest.rs -> :233,:519 (`via` fully covers); `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/via-only/mid/src/lib.rs` | CLEAN | grep -n '"via-only"' xtask/src/selftest.rs -> :233,:519 (`via` fully covers); `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/fixtures/via-only/src/lib.rs` | CLEAN | grep -n '"via-only"' xtask/src/selftest.rs -> :233,:519 (`via` fully covers); `test -e` -> PRESENT, file is inside a root the selftest walks | - |
| `xtask/src/audit_cmd.rs` | CLEAN | git grep -n "audit_cmd::" xtask/src -> cli.rs:75 and gates/audit_ledger.rs:177,:728; `git grep -n "xtask ledger" scripts` -> verify-1.6.0-done.sh:1044. Every nonexistent path literal is inside the #[cfg(test)] block (>=1900); `grep -n f64 xtask/src/audit_cmd.rs` -> :1488 `clean_pct`, printed at :1806 only, never compared to a threshold | - |
| `xtask/src/conformance_check/mod.rs` | CLEAN | Full read; every load path returns Result or an explicit Row::fail; `grep -n "rev-parse" ` -> :163 resolves HEAD through cx.git | - |
| `xtask/src/conformance_check/selftest.rs` | CLEAN | Full read; 8 cases, each asserting a Status AND a required substring, including a missing-manifest and an unparseable-JSON RED case | - |
| `xtask/src/discovery.rs` | CLEAN | Full read. `git grep -n "discovery::" xtask/src` -> full_gate.rs:596,:652,:667,:1011,:1034. `xtask_gate_names` reads ONLY the text passed in; I replayed it over .github/workflows/ci.yml in python -> 38 gate names, matching `git grep -oE "xtask gate [a-z0-9-]+" .github/workflows/ci.yml \| sort -u` | - |
| `xtask/src/gates/changelog.rs` | FINDING | Every one of the 9 owed rows has >=1 Row::pass and >=1 Row::fail site (`for r in ROW_SHAPE..ROW_VERSION_HAS_NOTES; do grep -c "Row::pass($r"`); python replay of parse()+rules over the real CHANGELOG.md -> 36 headings, 0 malformed, 0 duplicate versions, 0 future-dated. `test -e scripts/changelog-lint.py` -> ABSENT, yet :515-596 still declares 12 parity probes. git grep -n -- "--parity" -- . ':!xtask/src' -> only docs/design/xtask-gates.md:829 (which calls it "temporary") and xtask/tests/cli.rs; control `git grep -c -- "--selftest" .github/workflows/ci.yml` -> 61. The legacy/parity hooks here are unreachable from the shipped pipeline | X-1201 |
| `xtask/src/gates/ci_umbrella.rs` | FINDING | Every selftest anchor string still present in ci.yml (COUNT=1 each); python reconciliation -> 32 jobs / 28 needs / 28 RESULTS, 0 membership offenders, floors 20/15/15 all live. But grep -n ROW_TIER -> the single case at :310-319 drives only rule_tier's ("fast", true) arm; the ("full", false) arm at :978-981 — the one the module doc :48-50 calls "the required check quietly not requiring it" — has no case. `test -e scripts/ci-umbrella-lint.py` -> ABSENT while :371-503 declares 13 probes. git grep -n -- "--parity" -- . ':!xtask/src' -> only docs/design/xtask-gates.md:829 (which calls it "temporary") and xtask/tests/cli.rs; control `git grep -c -- "--selftest" .github/workflows/ci.yml` -> 61. The legacy/parity hooks here are unreachable from the shipped pipeline | X-1220, X-1201 |
| `xtask/src/gates/config_schema/scan.rs` | FINDING | grep -n in_char xtask/src/gates/config_schema/scan.rs -> :95 (init false), :111 (read), :119 (set false) — NOTHING sets it true, so the char-literal branch at :111-124 is unreachable. Control: `grep -n in_str` -> :94,:98,:106 AND :125 `in_str = true`. The doc at :88 claims "String and char literals are left intact" | X-1218 |
| `xtask/src/gates/conformance_sync/mod.rs` | FINDING | git grep -n "cx.git(\\|rev-parse" xtask/src/gates/conformance_sync/ -> rc=1, NO hits (control: `git grep -n "cx.git(" construction/ceilings.rs` -> :408). ROW_FRESHNESS claims "every armed passing verdict's commit equals the release commit", but the gate never reads the tree's sha | X-1217 |
| `xtask/src/gates/conformance_sync/render.rs` | FINDING | sed -n "292,312p" -> assess() computes `commit` as the MODE of the armed passing verdicts' own commits, then :340 reds only `v.commit != commit`. Measured: all 10 conformance/verdicts/*.json are armed+pass on 67ee7910, so the mode IS 67ee7910, stale list is empty, row PASSES; `git rev-list --count 67ee7910..HEAD` -> 574. Also `git grep -n cert_id xtask` -> 2 hits, both doc comments; `git grep -nE "expire\|SystemTime" conformance_sync/` -> `expires` is copied to the manifest and never compared to a clock | X-1217, X-1219 |
| `xtask/src/gates/conformance_sync/selftest.rs` | FINDING | sed -n "208,228p" -> the sole :freshness case moves ONE verdict off the anchor, leaving 9 agreeing, so it proves only the minority-disagrees arm — the arm a wholesale-stale set cannot trip. Registry fixtures use only `conformant`/`vendor-blessed`, so Tier::Certified/Capable/EvidenceOnly are never constructed by any fixture. 13 cases vs CASE_FLOOR=12 | X-1217, X-1219 |
| `xtask/src/gates/construction/external.rs` | CLEAN | git grep -n "external::" xtask/src/gates/construction.rs -> :322,:323,:523; every fn reachable and overlay-plantable | - |
| `xtask/src/gates/construction/model.rs` | CLEAN | grep -n "pure_auth\\|egress_auth" qa/construction.toml -> the kind_globs split this file documents is already collapsed to one `auth` key, matching the refusal logic | - |
| `xtask/src/gates/denylist_gate.rs` | CLEAN | grep -n '"denylist"' xtask/src/gates/mod.rs -> registered :2332; all three selftest fixture trees present (`find xtask/fixtures/{renamed-rule-table,no-crates-dir,dirty-plane}`) | - |
| `xtask/src/gates/design_bindings.rs` | FINDING | sed -n "187,193p" (doc: ROW_REGEN "owed only under --strict") vs `owed()`/`run()` at :200-210,:241-242 which push it unconditionally; DesignBindingsGate is a unit struct with no `strict` field. git grep -n -- "--parity" -- . ':!xtask/src' -> only docs/design/xtask-gates.md:829 (calls it "temporary") and xtask/tests/cli.rs; control `git grep -c -- "--selftest" .github/workflows/ci.yml` -> 61. The legacy/parity hooks in this file are unreachable from the shipped pipeline | X-1213, X-1201 |
| `xtask/src/gates/design_bindings/build.rs` | CLEAN | test -e docs/design/ARCHITECTURE.md testing/shadow-oracle/cells.json qa/design-bindings.json -> all present; python json load -> 104/104 bindings mapped, 0 unmapped | - |
| `xtask/src/gates/design_bindings/json.rs` | CLEAN | Selftest `the_committed_ledger_round_trips_byte_for_byte` reads and re-dumps qa/design-bindings.json; parser/writer read by hand, no drift | - |
| `xtask/src/gates/design_bindings/selftest.rs` | CLEAN | Full read: 20+ prove_red/prove_rows_red/prove_rows_green cases, each keyed to a real arm in verify.rs; the one standing red (note-witness/PB-58) is named rather than hidden | - |
| `xtask/src/gates/design_bindings/tables.rs` | FINDING | 23 SEED rows sampled with `test -e`/`grep "fn <name>"` -> all 23 resolve. But PB-58s NOTES prose at :606 cites `crates/busbar-caps/src/decision.rs`; `test -d crates/busbar-caps` -> absent (control: `test -e crates/busbar-contract/src/caps/decision.rs` -> present) | X-1207 |
| `xtask/src/gates/design_bindings/verify.rs` | FINDING | Re-ran `tokens()`+`is_witness_shaped()` (:614,:632) in python over PB-58s real note text -> flagged []: a bare path is split on `/` and `.` into segments with no underscore, so no path token is ever witness-shaped | X-1207 |
| `xtask/src/gates/duplex_ws_default_edge.rs` | FINDING | Its five dependency claims verified live with `cargo tree -e no-dev --offline` (busbar-kernel=0 tungstenite, busbar=4, --no-default-features=0) and a rotted feature name exits 101 — the rule is armed. git grep -n -- "--parity" -- . ':!xtask/src' -> only docs/design/xtask-gates.md:829 (calls it "temporary") and xtask/tests/cli.rs; control `git grep -c -- "--selftest" .github/workflows/ci.yml` -> 61. The legacy/parity hooks in this file are unreachable from the shipped pipeline; 4 hooks | X-1201 |
| `xtask/src/gates/hot_path_alloc.rs` | FINDING | git grep -n "cargo bench" -- .github scripts qa -> the ONLY executable invocation is qa/segments.toml:256 `cargo bench --workspace --no-run`; control `git grep -c "cargo test" .github/workflows/ci.yml` -> 41. The bench `main` that carries `assert_eq!(ALLOC_COUNT, 0)` never runs | X-1202 |
| `xtask/src/gates/hot_path_perf.rs` | FINDING | Same command; plus `grep -n busbar-core crates/busbar-kernel/benches/*.rs` -> both bench headers document `cargo bench -p busbar-core`, and `ls crates \| grep -c busbar-core$` -> 0 (control: busbar-kernel -> 1) | X-1202 |
| `xtask/src/gates/instance_noun_neutrality.rs` | FINDING | grep -n min_files xtask/src/gates/instance_noun_neutrality.rs -> :445 `.min_files(1)` over ["crates"], against `git ls-files "crates/**/*.rs" \| wc -l` -> 1611; and `categorize()` :425-430 names 4 crates absent from `ls crates` | X-1209, X-1212 |
| `xtask/src/gates/inventory_coverage.rs` | FINDING | Whole gate re-derived in python over HEAD inputs: 8 inventory files / 552 ids / 2318 cells, family_summary byte-matches qa/inventory-coverage.json, 266 gaps all named, 0 stale — the gate is live and correct. git grep -n -- "--parity" -- . ':!xtask/src' -> only docs/design/xtask-gates.md:829 (calls it "temporary") and xtask/tests/cli.rs; control `git grep -c -- "--selftest" .github/workflows/ci.yml` -> 61. The legacy/parity hooks in this file are unreachable from the shipped pipeline; 3 hooks | X-1201 |
| `xtask/src/gates/inventory_ref.rs` | FINDING | Replayed resolve_prefix over qa/design-bindings.json: 104 bindings, alias hits {proxy-hooks:27, routes-admin:18, auth-secrets:11, config:20, plugins-stores:8, governance:17, ops:10, dialects:13} and `1.5.5-behaviour`: 0. sed -n "108,120p" -> starts_with_word requires is_ascii_alphabetic(); the alias key at :78 starts with the digit `1` | X-1203, X-1201 |
| `xtask/src/gates/kernel_token_wire_purity.rs` | FINDING | grep -n SCAN_FLOOR -> :38 = 8, comment claims "Eleven production files"; `find crates/busbar-kernel/src -name "*.rs" \| grep -v /tests/ \| grep -v _tests.rs \| wc -l` -> 203. All 12 WIRE_FIELDS are 0 hits today (control `grep -rln tokens_in crates/busbar-kernel/src` -> 3 files) | X-1204, X-1201 |
| `xtask/src/gates/kind_isolation/inputs.rs` | FINDING | sed -n "755,770p" -> the corpus is one floorless `cx.walk(&WalkSpec::new(["."]).ext("toml"))` and the predicate is `name == "config.toml" && rel.contains(".cargo/")`. sed -n "908,915p" xtask/src/ctx.rs -> `if name == "target" \|\| name.starts_with('.') { continue; }` — collect() never descends a dotdir, so that predicate is unsatisfiable in production. `ls -la .cargo/config.toml` -> present, 715 bytes. The selftest goes red only because Ctx::list injects overlay paths when the root is "." | X-1221 |
| `xtask/src/gates/kind_isolation/truths.rs` | CLEAN | Python replay of plugin_kind_keys + ledger_kinds over qa/construction.toml and qa/kind-isolation.toml -> the 10 construction keys equal CONSTRUCTION_KIND_KEYS exactly; 21 ledger kinds, FORBIDDEN present [], NOT-in-table []; all 3 selftest needles present at :97-98 | - |
| `xtask/src/gates/map_proof.rs` | FINDING | grep -n unbound_figures xtask/src/gates/map_proof.rs -> :1341,:1384,:1736,:1744 — :1736/:1744 are both inside the `bound_detail` FORMAT STRING; sed -n "1748,1760p" shows ROW_BOUND is decided by `if orphans.is_empty()` alone. Python replay of collect_figures+integers_in over the 7 CORPUS docs -> 2635 bold figures, 1661 (63%) bound by no `# ->` | X-1200, X-1205 |
| `xtask/src/gates/money_invariants.rs` | FINDING | All 8 MONEY_RECORDS present in crates/busbar-contract/src/records.rs (control: `grep -c "struct NoSuchRecord" ` -> 0); token_in_ident replayed -> plugin_keyed [], stored_price []. `git grep -nE "Posted::settle(_late)?\(" crates` classified -> 66 TEST, 8 PROD (2 doc comments), and one of the 6 real ones is crates/busbar/src/root/units_llm.rs:875, a PER-PLANE unit module admitted by the crate-granular root "crates/busbar/" | X-1208 |
| `xtask/src/gates/no_self_filed_issues.rs` | FINDING | grep -n WF_DIR -> :43 = ".github/workflows"; `ls -d .github/*/` -> actions/ ISSUE_TEMPLATE/ scripts/ workflows/ — a composite action carries `runs.steps[].run:`, the same shell the gate hunts, and is never read. DISCOVERY_FLOOR=5 vs 28 workflow files. git grep -n -- "--parity" -- . ':!xtask/src' -> only docs/design/xtask-gates.md:829 (calls it "temporary") and xtask/tests/cli.rs; control `git grep -c -- "--selftest" .github/workflows/ci.yml` -> 61. The legacy/parity hooks in this file are unreachable from the shipped pipeline | X-1210, X-1201 |
| `xtask/src/gates/no_tracked_ignored.rs` | CLEAN | git ls-files -ci --exclude-standard \| wc -l -> 0; positive control `git ls-files -c \| wc -l` -> 3883. Plant and un-plant both route through Ctx::tracked_ignored overlay key | - |
| `xtask/src/gates/package_selectors.rs` | FINDING | Python re-implementation of universe/scan_commands/scan_matrix/scan_rust_commands/parse_decl over the real tree -> universe 467 (floor 40), 206 sites (floor 120), 0 DEAD selectors, 3 decls all live and >=30 chars — the gate is live. UNIVERSE_FLOOR=40 (:114) sits against 51 workspace members in a tree that is actively folding crates | X-1211 |
| `xtask/src/gates/plane_abi_neutrality.rs` | FINDING | grep -n "min_files(1)" -> :222, over `find crates -name "*.rs" \| wc -l` -> 1637; `declared_plane_keys` returns Ok(vec![]) when it recognises no `pub const PLANE_DECL`, and the consumer then seeds from the PLANE_KEYS const and filters against the BANNED const — two literals in this file agreeing, which the row's own doc says it was rewritten to eliminate. `find . -name "plane-abi-neutrality*"` -> no output (control: `find . -name "plane-noun-gate*"` -> ./scripts/plane-noun-gate.sh) while :454-786 carries a 166-line translator. git grep -n -- "--parity" -- . ':!xtask/src' -> only docs/design/xtask-gates.md:829 (which calls it "temporary") and xtask/tests/cli.rs; control `git grep -c -- "--selftest" .github/workflows/ci.yml` -> 61. The legacy/parity hooks here are unreachable from the shipped pipeline | X-1222, X-1201 |
| `xtask/src/gates/plane_purity/freeze.rs` | FINDING | git grep -n "\.sites" xtask/src/ -> ONE hit, freeze.rs:119 `out.sites.push(site)` — a write with no reader. Control: `git grep -n uprefs xtask/src/` -> 7 hits including the read at plane_purity/mod.rs:275. The declared capability at :82-83 ("Every remaining site, file:line, in walk order") does not ship | X-1223 |
| `xtask/src/gates/plane_purity/strict.rs` | CLEAN | Python replay of parse_ceilings over qa/plane-purity-strict.toml -> all 10 keys At(n) (PATH-INCLUDE=0, SYMBOL=61, TYPE=13, KEY=377, DIALECT=456, BACKWARDS=33, llm=24, mcp=1, a2a=3, voice=0), matching scanner::CATEGORIES + planes::PLANE_KEYS; `git grep -n "not a bare integer"` -> mod.rs:893 proves the Uncomparable arm can go red | - |
| `xtask/src/gates/qa_gate_dispatch.rs` | CLEAN | Python diff of all 5 jobs' name/needs/runs-on/timeout-minutes plus the `on:` block, qa-gate.yml vs qa-gate.dispatcher.json -> MISMATCHES: none; `test -e` on all three subjects -> PRESENT; `git grep -n write_declared` -> cli.rs:302 | - |
| `xtask/src/gates/reachability.rs` | FINDING | sed -n "1240,1250p;1296,1300p" -> both unit-path and root-reach score `None => Ok(...)` when the module file is simply absent; `ls crates/busbar/src/root/` has no units_decision.rs, and the FIX_RED fixture root/mod.rs DOES declare `pub mod units_decision`, so no selftest case plants the absent-module shape. ALREADY ON THE-LIST as X-63 (VERIFIED, carried) — independently re-verified here, NOT re-raised | X-63 (existing) |
| `xtask/src/gates/response_header.rs` | FINDING | Each Rule.allow needle grepped -> exactly one non-test hit in exactly the file the rule names (busbar-substrate-values/src/proxy/mod.rs, busbar-llm/src/engine/wire.rs, busbar-kernel/src/router.rs — all present). git grep -n -- "--parity" -- . ':!xtask/src' -> only docs/design/xtask-gates.md:829 (calls it "temporary") and xtask/tests/cli.rs; control `git grep -c -- "--selftest" .github/workflows/ci.yml` -> 61. The legacy/parity hooks in this file are unreachable from the shipped pipeline; 3 hooks | X-1201 |
| `xtask/src/gates/seal_witness.rs` | CLEAN | git grep -n -F "KernelSeal::acquire_for_kernel(" crates \| grep -v tests -> 5 hits, 4 of them `//!` doc lines plus the one production minter at crates/busbar-kernel/src/teller.rs:94, inside KERNEL_ROOT; all 11 ZOO names appear only on stripped comment lines; 767 production files after EXCLUDE vs SCAN_FLOOR=200 | - |
| `xtask/src/gates/settings_leak.rs` | FINDING | The `crates/busbar-core/src/planted_*.rs` literals (:502-609) are selftest Overlay plants, and ctx.rs `list()` explicitly admits an overlay path under a directory that does not exist yet; the real run() root is population-derived over the live `crates/`. git grep -n -- "--parity" -- . ':!xtask/src' -> only docs/design/xtask-gates.md:829 (calls it "temporary") and xtask/tests/cli.rs; control `git grep -c -- "--selftest" .github/workflows/ci.yml` -> 61. The legacy/parity hooks in this file are unreachable from the shipped pipeline; 3 hooks | X-1201 |
| `xtask/src/gates/structure_lint/axis.rs` | CLEAN | test -e over every scope/allowed path (crates/api/src/operation.rs, .../proto, .../handlers, busbar-substrate-values/src/transport.rs, busbar-kernel/src/registry.rs) -> all present; the sole ledgered exception still matches (registry.rs:367 `left.transport == right.transport`) | - |
| `xtask/src/gates/structure_lint/census.rs` | CLEAN | 5 wire-word rows spot-checked: `git grep -n "io.modelcontextprotocol/protocolVersion" crates` -> exactly one non-test hit (busbar-plane-mcp/src/codec.rs:116); same shape for clientCapabilities, mcp-protocol-version, mcp-method, mcp-name | - |
| `xtask/src/gates/structure_lint/choke_points.rs` | CLEAN | All 25 owner/allow/class-test paths run through a `test -e` loop -> all OK; all 10 class-test fns found with `grep -nE "fn[[:space:]]+<name>\("` | - |
| `xtask/src/gates/structure_lint/corpus.rs` | CLEAN | find crates -name "*.rs" \| grep -v tests \| grep -v benches \| wc -l -> 772, against CANDIDATE_FLOOR = 200 | - |
| `xtask/src/gates/structure_lint/fn_scoped.rs` | CLEAN | grep -nE "fn[[:space:]]+try_admit" governance/state.rs, `fn decl_for` proto/registry.rs, resolve/revalidate/visible_catalogue in mcp/client/dispatch.rs -> all present at the named lines | - |
| `xtask/src/gates/structure_lint/hybrid.rs` | CLEAN | Read in full (64 lines); the directory set is walk-derived, there is no static path or floor that can drift | - |
| `xtask/src/gates/structure_lint/inline_tests.rs` | CLEAN | Read in full; the `[]([:space:]]` terminator class is deliberate (distinguishes test/test_case from testing); the corpus it runs over is already proven non-empty by corpus.rs | - |
| `xtask/src/gates/structure_lint/mod.rs` | FINDING | grep -n "pub mod structure_lint" xtask/src/gates/mod.rs -> :64; ci.yml:296,:298 run it selftest+plain; all 36 OWED rows wired in Findings::rows(). git grep -n -- "--parity" -- . ':!xtask/src' -> only docs/design/xtask-gates.md:829 (calls it "temporary") and xtask/tests/cli.rs; control `git grep -c -- "--selftest" .github/workflows/ci.yml` -> 61. The legacy/parity hooks in this file are unreachable from the shipped pipeline; has_legacy_adapter->true at :391 and legacy_rows at :395 | X-1201 |
| `xtask/src/gates/structure_lint/plane_dups.rs` | CLEAN | docs/code-layout.md:140 documents the mcp/a2a-only scope as intentional design, so it is not roster drift | - |
| `xtask/src/gates/structure_lint/plane_store.rs` | CLEAN | test -d crates/busbar-kernel/src/plane -> yes; `git grep -c "fn set_sink"` -> 3 hits; `pub struct BootCtx` found at registry.rs:85 | - |
| `xtask/src/gates/structure_lint/roots.rs` | FINDING | `ls crates` has no crate starting `busbar-proto-`, yet proto_root_of (:58-62) ORs that prefix in. The OR keeps ROW_PROTO_ROOTS armed today via busbar-llm/busbar-mcp/*-codec, so this is a dead disjunct rather than a blind rule | X-1214 |
| `xtask/src/gates/structure_lint/selftest.rs` | CLEAN | Python regex + manual grep over every `covers`/`tree_case`/`table_case` argument -> all 36 OWED row ids named by at least one case; read all 883 lines | - |
| `xtask/src/gates/structure_lint/translate.rs` | DELETABLE | test -e scripts/structure-lint.sh -> MISSING; `git log --diff-filter=D --summary -- scripts/structure-lint.sh` -> fce359cd7 (2026-09-07) "the structure-lint shell is deleted; the gate at parity with it is what runs". git grep -n -- "--parity" -- . ':!xtask/src' -> only docs/design/xtask-gates.md:829 (calls it "temporary") and xtask/tests/cli.rs; control `git grep -c -- "--selftest" .github/workflows/ci.yml` -> 61. The legacy/parity hooks in this file are unreachable from the shipped pipeline. The only callers of translate()/legacy_rows() are two #[test] fns in xtask/tests/infra.rs:1437,:1455 that hand-build a synthetic LegacyRun. 596 lines, no shipping caller | X-1201 |
| `xtask/src/gates/workspace_deps.rs` | FINDING | sed -n "66,72p" claims "today's counts (63 members, 62 manifests)"; `awk "/^members = \[/,/^\]/" Cargo.toml \| grep -c '"crates/'` -> 49 and `find crates -maxdepth 2 -name Cargo.toml \| wc -l` -> 49. MIN_MEMBERS=8 against 49. git grep -n -- "--parity" -- . ':!xtask/src' -> only docs/design/xtask-gates.md:829 (calls it "temporary") and xtask/tests/cli.rs; control `git grep -c -- "--selftest" .github/workflows/ci.yml` -> 61. The legacy/parity hooks in this file are unreachable from the shipped pipeline | X-1211, X-1201 |
| `xtask/src/gitp.rs` | CLEAN | Full read: git()/ask()/check_ignore() all Result-typed, 3-valued exit-status handling correct; `git grep -n "gitp::" xtask/src` -> callers in ctx.rs, audit.rs, loc.rs | - |
| `xtask/src/json_lite.rs` | CLEAN | Full read: parse() is Result<Json,String>; trailing bytes and lone surrogates are hard errors; `git grep -n "json_lite::parse" xtask/src` -> 6 gate callers (audit.rs, audit_ledger.rs, inventory_coverage.rs, teller_steps.rs) | - |
| `xtask/src/lib.rs` | CLEAN | Every one of the 24 `pub mod` declarations resolves to a file on disk (`ls xtask/src`); no module is declared-but-absent and no file under xtask/src is undeclared | - |
| `xtask/src/loc.rs` | CLEAN | Full read: :716 `let mut red = !report.errors.is_empty();` — a parse failure hard-fails the gate rather than counting 0 lines; `sum == 0` is also a FAIL | - |
| `xtask/src/loc/classify.rs` | CLEAN | Full read: real syn::parse_file at :197 plus TokenStream::from_str at :201; Err is propagated, never counted as zero | - |
| `xtask/src/loc/config.rs` | CLEAN | Full read (80 lines): explicit `if crate_roots.is_empty() { return Err(...) }` at :40-48 and the same for empty groups at :53-58 — no zero threshold is accepted silently | - |
| `xtask/src/loc/render.rs` | CLEAN | Full read; a writer, not a reader; `errors` are surfaced explicitly in the JSON output rather than dropped | - |
| `xtask/src/main.rs` | CLEAN | 21 lines, read in full; arms the process watchdog then delegates to cli::main — `git grep -n "enable_process_watchdog" xtask/src` confirms the binary is the only arming site, which is the documented intent | - |
| `xtask/src/manifest.rs` | CLEAN | Full read: unreadable() (:225) explicitly reports section headers and dotted keys it cannot place rather than skipping them; caller kind_isolation.rs:2207. The `busbar-testkit` literal (:695) is a synthetic unit-test fixture | - |
| `xtask/src/scan.rs` | CLEAN | Full read: a heuristic lexer by design, with its past defects (nested block comments, raw strings, char-literal braces) documented and covered; driven by xtask/tests/infra.rs | - |
| `xtask/src/selftest.rs` | FINDING | sed -n "66,100p": check() with an empty `expect_offenders` asserts only `hits.is_empty()`. denylist::run_on (denylist.rs:1215) prints "not found in cargo metadata output; skipped" to stderr and returns without the closure half, so a GREEN case cannot tell "the walk ran and found nothing" from "the walk did not run". The RED cases do fail closed, so the battery as a whole still refuses | X-1216 |
| `xtask/src/sha256.rs` | CLEAN | Transcribed line-for-line into python and matched hashlib.sha256 on "", "abc", the 64-byte block boundary and 1e6 x "a" — all MATCH; caller audit.rs:663 (tree_hash), not test-only | - |
| `xtask/src/toml_doc.rs` | CLEAN | Full read: parse_str returns Result; every unrecognized token or line is an Err carrying a line number — the sibling reader that got the treatment toml_lite did not | - |
| `xtask/src/toml_lite.rs` | FINDING | grep -n "pub fn parse\\|-> Document\\|Result<" xtask/src/toml_lite.rs -> :81 and :90 both return a bare `Document`; sed -n "150,200p" shows the per-line dispatch tries [[..]], [..], then split_once("=") with NO else arm, so any other line is dropped silently. `grep -c toml_lite xtask/tests/readers.rs` -> 0 (control: `grep -c json_lite` -> 20) | X-1206 |
| `xtask/tests/config_schema.rs` | CLEAN | Python assertion-scan -> 45/45 tests contain a real assert/expect; the suite carries its own CASE_FLOOR=40 honesty floor against 45 actual | - |
| `xtask/tests/gate_ceiling.rs` | CLEAN | Full read: proves hang->RED under a real watchdog thread (within()), and asserts ceiling-override precedence, "0 disables", and unreadable->default | - |
| `xtask/tests/gate_mutation_proof.rs` | CLEAN | grep -rn XTASK_GATE_MUTATION_PROOF .github -> gate-mutants.yml:186 sets it to "1" and :192 runs the test; the env gate is real and exercised by a required check, not a silent skip | - |
| `xtask/tests/git_batch.rs` | CLEAN | Full read: a 4000-blob pipe-buffer-deadlock proof under the within() watchdog, plus an architectural test that walks xtask/src in Rust (not a shell glob) to ban piped stdin outside gitp.rs | - |
| `xtask/tests/infra.rs` | FINDING | sed -n "318,330p" -> the comment cites "crates/busbar-core/src/admin/v1/contract/taxonomy.rs:610"; `ls crates` has no busbar-core and `git log --diff-filter=D --summary -- "crates/busbar-core/*"` -> 673ecdaaa "absorb busbar-core INTO busbar-kernel; delete busbar-core". Also holds the only two callers of structure_lint::translate (:1437,:1455) | X-1215 |
| `xtask/tests/readers.rs` | FINDING | grep -c toml_lite xtask/tests/readers.rs -> 0; control `grep -c json_lite` -> 20. The file that exists to hold the shared readers' own cases has zero cases for the one reader with no error path | X-1206 |

## ROWS RAISED

### X-1217 · `conformance-sync`'s freshness rule is its own baseline — it anchors to the MODE of the very verdict set it judges, so a WHOLESALE-stale set is GREEN, and ten customer-facing README badges are 574 commits past the green that earned them
```
CLASS:     customer-surface · instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `xtask/src/gates/conformance_sync/mod.rs` opens by calling a stale certification claim "a
           company-killer", and ROW_FRESHNESS is documented as: *"every armed passing verdict's
           `commit` equals the release commit — a pass carried over from an older sha is RED
           (§5.2)"*. There is no release commit in that sentence's sense. `render.rs::assess`
           INVENTS one out of the data it is about to judge:

             $ sed -n '292,312p' xtask/src/gates/conformance_sync/render.rs
                 // The release commit: the mode of the armed passing verdicts' commits.
                 for (_, v) in &verdicts { if v.armed && v.status == "pass" && !v.commit.is_empty()
                     { *counts.entry(v.commit.clone()).or_default() += 1; } }
                 let commit = counts.iter().max_by_key(|(_, n)| **n).map(|(c, _)| c.clone())…
             $ sed -n '340p' xtask/src/gates/conformance_sync/render.rs
                 …reds only when `v.commit != commit`

           So the rule is "every verdict agrees with the most popular verdict". The tree's own sha
           is never consulted:

             $ git grep -n "cx.git(\|rev-parse" -- xtask/src/gates/conformance_sync/
             (no output, rc=1)
             CONTROL $ git grep -n "cx.git(" -- xtask/src/gates/construction/ceilings.rs
             xtask/src/gates/construction/ceilings.rs:408: let head = cx.git(&["rev-parse","HEAD"])…

           Measured on HEAD — all ten verdicts are unanimous, so the mode is the stale sha and the
           stale list is empty:

             $ python3  # mode of armed+pass conformance/verdicts/*.json
             armed+pass verdict commits: {'67ee7910305068c2c86ccd1811d4bd189973b45b': 10}
             anchor = 67ee7910305068c2c86ccd1811d4bd189973b45b
             HEAD   = a3ba43000f85da5dbd9fc288e4b32dcafde365dd
             $ git rev-list --count 67ee7910..HEAD
             574

           `conformance-sync` is run on every push (`ci.yml:443,:445`) and is GREEN over this.
           What it certifies is on the customer surface:

             $ grep -n "conformant" README.md | head -3
             README.md:31: …badge/A2A-conformant-2ea44f" alt="A2A conformant"
             README.md:32: …badge/LLM_Anthropic-spec--conformant-2ea44f"
             README.md:33: …badge/LLM_Bedrock-spec--conformant-2ea44f"      (10 badges in all)

           The selftest cannot catch it. Its one freshness case (`selftest.rs:208-228`) moves a
           SINGLE verdict off the anchor, leaving nine agreeing — the minority-disagrees arm is the
           only arm this construction can red. A case that restamped ALL ten to one stale sha would
           pass green today, which is the proof the rule is missing.
ACTION:    In `render.rs::assess`, stop deriving the anchor from the data it judges. Take it from the tree
           — `cx.git(&["rev-parse","HEAD"])?.trim()`, the shape `construction/ceilings.rs:408`
           already uses — and red every armed `pass` whose `commit` is not that anchor (the release
           tag's sha on the release arm). Add the selftest case that rewrites EVERY verdict commit
           to one stale sha and requires ROW_FRESHNESS red. Separately: the write half
           `render.rs:13-15` describes ("the release pipeline drops the downloaded artifacts here
           before `--write`") exists in no workflow — `conformance/verdicts/*.json` are ten
           hand-committed files — so either wire the jobs that actually measure (`llm-conformance`,
           ci.yml:3417) to emit verdicts, or the manifest can only ever be hand-maintained truth.
```

### X-1200 · `map-proof:bound` measures every unbindable figure in the corpus, prints it, and never judges it — 1,661 of 2,635 printed figures (63%) have no command that produces them, and the row passes
```
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  The row's own contract, `xtask/src/gates/map_proof.rs:108`, is two claims:

             /// Every `# ->` is attached to a command, and every bold figure has a command that
             /// produces it.

           and the module header calls the second the important one: *"**A figure nobody can
           re-derive is the worst case, not the absent case.**"* The census computes it. The
           verdict ignores it:

             $ grep -n "unbound_figures" xtask/src/gates/map_proof.rs
             1341:    pub unbound_figures: Vec<(&'static str, usize, i64)>,
             1384:                out.unbound_figures.push((src.path, *line, *n));
             1736:            .unbound_figures
             1744:            c.unbound_figures.len(),

           :1736 and :1744 are both inside `bound_detail`, a `format!` string. There is no other
           reference — the value never reaches a comparison, a threshold, or a `Row::fail`:

             $ sed -n '1748,1760p' xtask/src/gates/map_proof.rs
                 rows.push(if orphans.is_empty() {
                     Row::pass(ROW_BOUND, "every `# ->` in the corpus is attached to a command", …)
                 } else {
                     Row::fail(ROW_BOUND, "a `# ->` expectation is printed with no command …", …)
                 });

           `orphans` is the FIRST claim only (a `# ->` with no command above it). The second claim
           — the one the header calls the worst case — is unjudged, so it cannot produce a NO.

           Magnitude, by replaying the gate's own `extract`/`collect_figures`/`integers_in` in
           python over the seven `CORPUS` documents:

             docs/design/1.6.0-map-proof.md        bold 1201  arrows 216  UNBOUND  285
             docs/design/1.6.0-ratchet-census.md   bold  361  arrows   3  UNBOUND  332
             docs/design/1.6.0-oracle-coverage.md  bold  120  arrows   7  UNBOUND  102
             docs/design/1.6.0-done-readout.md     bold   33  arrows   0  UNBOUND   33
             docs/design/1.6.0-instrument-audit.md bold   87  arrows   5  UNBOUND   84
             docs/design/1.6.0-gate-sweep.md       bold  131  arrows   5  UNBOUND  123
             docs/design/1.6.0-LEDGER.md           bold  702  arrows   0  UNBOUND  702
             TOTAL bold 2635  UNBOUND 1661  (63%)

           (The python is a re-implementation, so treat 1,661 as the order of magnitude; the
           STRUCTURAL fact — that no code path compares `unbound_figures` to anything — is exact
           and is the finding.)
ACTION:    Give the second claim its own row rather than folding it into ROW_BOUND's detail string: add
           `map-proof:derivable`, owed and reconciled like the rest, RED when `unbound_figures` is
           non-empty, with a corpus-wide ratchet so the 1,661 can be burned down instead of
           arriving as one unreadable wall. Keep ROW_BOUND for orphans, where its title is already
           accurate. Add a selftest case planting a bold figure no `# ->` produces and requiring
           the new row RED — today no case can distinguish the two claims.
```

### X-1221 · `kind-isolation`'s `.cargo/config.toml` redirect rule tests a predicate the walker structurally cannot satisfy — `collect()` skips every dotdir, so the `[source] replace-with` arm is dead in production and red only under the plant
```
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `redirect_findings` takes its whole corpus from one walk and then asks two questions of it:

             $ sed -n '755,770p' xtask/src/gates/kind_isolation/inputs.rs
                 let files = match cx.walk(&WalkSpec::new(["."]).ext("toml")) { … };
                 …
                 let is_cargo_toml   = name == "Cargo.toml";
                 let is_cargo_config = name == "config.toml" && rel.contains(".cargo/");

           The walker cannot deliver the second:

             $ sed -n '908,915p' xtask/src/ctx.rs
                 if name == "target" || name.starts_with('.') { continue; }

           `collect()` never descends a dotdir, so no path containing `.cargo/` is ever in `files`,
           and `is_cargo_config` is unsatisfiable on any real tree. Replaying `ctx.rs::collect`
           over root `.` with `ext("toml")` in python:

             toml files the walk yields: 105
               '.cargo/config.toml' present?              -> False
               CONTROL 'Cargo.toml' present?              -> True
               CONTROL 'crates/busbar/Cargo.toml' present?-> True
               files matching is_cargo_config:            -> []

           The subject exists and is exactly where a redirect would go:

             $ ls -la .cargo/config.toml
             -rw-r--r--  1 matthew  staff  715 Sep 17 12:58 .cargo/config.toml

           and the module names it as a subject (`inputs.rs:1043`): *"`[patch]`, `[replace]` and
           `.cargo/config.toml`'s `[source] replace-with` substitute one crate for another AFTER
           every manifest in this tree has been read"*.

           WHY THE SELFTEST IS STILL GREEN-THEN-RED: the plant reaches the rule by a route
           production never takes. `Ctx::list` injects overlay paths whenever the root is `.`
           (`ctx.rs:575-589`), so `ov.set(".cargo/config.toml", …)` lands in the file list even
           though the directory is never walked. The RED proof is real; the production scan is
           blind. A `[source.crates-io] replace-with` committed to `.cargo/config.toml` leaves
           `kind-isolation:build-inputs` PASS, and no other reader covers it:

             $ git grep -n "\.cargo/config" -- xtask/src/ scripts/ .github/
             (only kind_isolation's own comment and plant, plus prose)

           Secondary, same function: that walk carries no `.min_files(…)`, so an `Ok(vec![])` from
           a filter change reports "no `[patch]` anywhere" — which the `Err` arm's own sentence
           calls "indistinguishable from a tree that has none".
ACTION:    Read the file by name instead of hoping the walk yields it: `if let Ok(text) =
           cx.read(".cargo/config.toml")` (the selftest already proves `cx.read` reaches it) and run
           the same header loop over it with `rel = ".cargo/config.toml"`, keeping the existing
           `patch_allows` exemption. Treat present-but-unreadable as a finding. Add
           `.min_files(80)` (measured 105) to the `WalkSpec::new(["."]).ext("toml")` walk so a
           collapsed manifest scan is refused rather than reported clean.
```

### X-1201 · THE PARITY SUBSYSTEM IS DEAD ACROSS THE HARNESS: `--parity` is invoked by no workflow, script or qa file, every legacy script it translates has been deleted, and 15 files in this slice still carry the adapters
```
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `--parity` is the ONLY entry point that reaches `has_legacy_adapter`/`legacy_rows`/
           `translate`/`parity_probes`, and it is reachable from nowhere that ships:

             $ git grep -n -- "--parity" -- . ':!xtask/src'
             docs/design/xtask-gates.md:829: …add a TEMPORARY `cargo xtask gate <name> --parity`…
             xtask/tests/cli.rs:105,110      (argument-error tests, legacy argv = /usr/bin/true)
             xtask/tests/infra.rs:1464       (a comment about the retired shell)
             CONTROL $ git grep -c -- "--selftest" .github/workflows/ci.yml
             61

           The doc itself calls it temporary. The other half of every parity pair is gone:

             $ for s in structure-lint.sh plane-abi-neutrality.sh changelog-lint.py \
                        ci-umbrella-lint.py config-schema.py g6-freeze-witness.sh; do
                 [ -e "scripts/$s" ] && echo "PRESENT $s" || echo "ABSENT  $s"; done
             ABSENT (all six)
             CONTROL $ ls scripts/*.sh | wc -l  ->  60   (the directory is there)

           Deleted deliberately, one gate at a time:
             $ git log --oneline --diff-filter=D -- scripts/structure-lint.sh
             fce359cd7 the structure-lint shell is deleted; the gate at parity with it is what runs
             $ git log --oneline --diff-filter=D --all -- scripts/plane-abi-neutrality.sh
             1abb1e45f the plane-ABI witness shell retires…

           Still declared in this slice (hook count per file):

             changelog.rs 1 · ci_umbrella.rs 1 · design_bindings.rs 3 · duplex_ws_default_edge.rs 4
             inventory_coverage.rs 3 · inventory_ref.rs 1 · kernel_token_wire_purity.rs 3
             no_self_filed_issues.rs 4 · plane_abi_neutrality.rs 3 · qa_gate_dispatch.rs 1
             response_header.rs 3 · settings_leak.rs 3 · structure_lint/mod.rs 2
             structure_lint/translate.rs 1 · workspace_deps.rs 1

           (`grep -cE 'fn has_legacy_adapter|fn legacy_rows|fn legacy_companions|fn legacy_env|fn
           parity_probes|fn translate|fn decolour'` per file; control: map_proof.rs -> 0.)

           No gate goes BLIND from this — every row these translators build is also built by `run`
           and red-proven by the selftests. It is Law 2: several hundred lines of capability that
           does not ship, carrying live-looking knowledge (legacy wordings, `Divergence`
           declarations, error arms) about counterparts that cannot be run. `structure_lint/
           translate.rs` is the extreme case and is marked DELETABLE on its own line: 596 lines
           whose only callers are two `#[test]` fns in `xtask/tests/infra.rs:1437,:1455` that
           hand-build a synthetic `LegacyRun`.
ACTION:    Retire the mechanism now that the conversion it existed for is finished: delete
           `has_legacy_adapter`, `legacy_rows`, `legacy_companions`, `legacy_env`, `parity_probes`,
           `translate`/`translate_check` and `decolour` from the 15 files above, delete
           `structure_lint/translate.rs` outright, and strike the "successor to scripts/X"
           sentences from the module docs (or restate them as "the legacy retired in <sha>").
           If the mechanism is being KEPT for gates still mid-conversion, make it self-policing in
           the same commit: have the registry assert that every gate returning
           `has_legacy_adapter() == true` names a script `Ctx::exists` can find. That claim is
           asserted by nobody today and is false for all of them — which is precisely why this rotted
           silently.
```

### X-1202 · `hot-path-perf` and `hot-path-alloc` gate budgets that are asserted inside benches nothing ever runs — the only `cargo bench` in the tree carries `--no-run`
```
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  Both gates' module docs say the measurement "runs in the perf lane". There is no perf lane:

             $ git grep -n "cargo bench" -- .github scripts qa
             qa/segments.toml:231: # `cargo bench` ran nowhere: not in .github/workflows/, not in scripts/…
             qa/segments.toml:238: # …`cargo bench --workspace --no-run` builds every bench target and
             qa/segments.toml:238:   asserts nothing about the figures
             qa/segments.toml:256: run = "cargo bench --workspace --no-run && cargo test --release …"
             CONTROL $ git grep -c "cargo test" .github/workflows/ci.yml  ->  41

           The only executable invocation in the repository carries `--no-run`, and qa/segments.toml
           says so in its own words. So `assert_hot_path_delta_under_budget()` (p50/p99 <
           HOT_PATH_BUDGET_NANOS = 1_000) and `assert_zero_per_token_host_calls()` and the alloc
           bench's `assert_eq!(ALLOC_COUNT, 0)` never execute — not in `.github/workflows`, not in
           `scripts/`. The rows `:delta-p50-under-1us`, `:delta-p99-under-1us`,
           `:per-token-host-calls-zero` and `:pod-batch-zero` assert the TEXT of a threshold that
           cannot be exceeded.

           The documented manual escape hatch is dead too, and names a crate that was dissolved:

             $ grep -n "busbar-core" crates/busbar-kernel/benches/*.rs
             plane_host_vtable_alloc.rs:37://! cargo bench -p busbar-core --bench plane_host_vtable_alloc
             plane_host_vtable_perf.rs:45://! cargo bench -p busbar-core --bench plane_host_vtable_perf
             $ ls crates | grep -cx busbar-core   ->  0
             CONTROL $ ls crates | grep -cx busbar-kernel  ->  1

           MITIGATING, and it should be stated: equivalent PROPERTIES are asserted by two tests that
           DO run — `crates/busbar-plugin/src/hot/tests/host_tests.rs:341` (named in
           qa/segments.toml:256) and `crates/busbar-contract/tests/capability_binding_zero_cost.rs:64`.
           Neither is what these two gates name, guard, or would notice the loss of.
ACTION:    Either (a) execute the benches for real in the `benches` segment — `cargo bench -p
           busbar-kernel --bench plane_host_vtable_perf --bench plane_host_vtable_alloc` — with one
           injected-red leg per knob (`BUSBAR_PERF_STREAM_CROSS=1`, `BUSBAR_ALLOC_INJECT=1` must
           exit non-zero), and add a row to each gate asserting that segment line still names the
           bench; or (b) delete both benches and re-point the two gates at the tests that actually
           run the measurement. Either way fix both bench headers' `-p busbar-core` to
           `-p busbar-kernel`. (The bench files are outside this slice.)
```

### X-1218 · `config_schema`'s comment stripper declares char-literal protection and never constructs it: `in_char` is initialised to false, read, and set to false — never set TRUE — so a `'\"'` switches comment-stripping off for the rest of the file
```
CLASS:     missing-code · instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  Three references, and not one of them arms the flag:

             $ grep -n "in_char" xtask/src/gates/config_schema/scan.rs
             95:    let mut in_char = false;
             111:        if in_char {
             119:                in_char = false;

             CONTROL — the sibling flag that IS armed:
             $ grep -n "in_str" xtask/src/gates/config_schema/scan.rs
             94:    let mut in_str = false;
             98:        if in_str {
             106:                in_str = false;
             125:            in_str = true;      <-- the assignment in_char does not have

           So the whole char-literal branch at :111-124 is unreachable, and the doc directly above
           the function is half false:

             $ sed -n '87,89p' xtask/src/gates/config_schema/scan.rs
             /// …String and char literals are left intact — the config types have string defaults
             /// with `//` inside URLs.

           rustc and clippy stay silent because the variable is both written and read.

           The consequence is not cosmetic. With the char arm dead, the `"` inside the char literal
           `'"'` falls through to `:126 if c == '"' { in_str = true; }`, and the stripper spends the
           rest of the file believing it is inside a string. Everything downstream (`items`,
           `match_arm_literals`, `lift_lists`, `serde_flag`) then reads commented-out grammar as
           live grammar — and its output is the FROZEN, additive-only config-schema fingerprint.
           Not live today (no tracked scanned file carries `'"'`), but three files one directory
           away do, and `crates/busbar-kernel/src/auth/mod.rs` IS tracked. The legacy this was
           ported from is gone (`ls scripts/config-schema.py` -> No such file), so there is no
           original left to diff the dropped branch against.
ACTION:    Add the missing arm beside `:126`:
             if c == '\'' { in_char = true; out.push(c); i += 1; continue; }
           guarded so a lifetime (`'de`, `'static`) does not open a literal — enter only when the
           next chars close as a char literal. Add a unit test asserting that
           `pub const QUOTE: char = '\"';` followed by a `// #[serde(rename = "ghost")]` line
           still blanks that comment. If the lifetime guard is too ugly to be right, delete
           :111-124 and change the doc at :88 to say char literals are NOT protected — but then the
           `'\"'` hole needs a refusal, because silently mis-scanning a frozen fingerprint is the
           worse half.
```

### X-1203 · `inventory-ref`'s `1.5.5-behaviour` alias can never resolve — `starts_with_word` demands `is_ascii_alphabetic()` and the alias key begins with a digit, so two bindings that DO name an inventory file are silently classed "nothing to check"
```
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `resolve_prefix` refuses a segment before the alias scan whenever `starts_with_word` is false:

             $ sed -n '110,120p' xtask/src/gates/inventory_ref.rs
             fn starts_with_word(segment: &str) -> bool {
                 … matches!(first, Some(c) if c.is_ascii_alphabetic())
             }
             $ sed -n '78p' xtask/src/gates/inventory_ref.rs
                 ("1.5.5-behaviour", "docs/design/1.5.5-BEHAVIOUR.md"),

           The key starts with the digit `1`, so the alias is a declaration with no possible
           construction. Replaying `resolve_prefix` over the real `qa/design-bindings.json`:

             104 bindings, 0 unrecognized, 0 missing files
             alias hits: {proxy-hooks:27, routes-admin:18, auth-secrets:11, config:20,
                          plugins-stores:8, governance:17, ops:10, dialects:13}
             '1.5.5-behaviour': ABSENT (0 hits)

           And the two bindings that cite it are silently dropped rather than checked:

             PB-72 inventory = '1.5.5-BEHAVIOUR precedence'
                   segment '1.5.5-BEHAVIOUR precedence'  starts_with_word=False
             PB-92 inventory = 'auth-secrets :151-161, :380, :389; 1.5.5-BEHAVIOUR trap'
                   segment 'auth-secrets :151-161, …'    starts_with_word=True
                   segment '1.5.5-BEHAVIOUR trap'        starts_with_word=False

           Two live consequences. If `docs/design/1.5.5-BEHAVIOUR.md` were renamed,
           `inventory-ref:file-exists` would stay GREEN — the precise failure the module doc
           describes ("a pointer nobody can follow is unfalsifiable"). And a digit-leading segment
           is a THIRD silent shape where the doc enumerates exactly two (a bare backtick source
           path, a `PB-N` self-reference), so `inventory-ref:prefix` under-reports as well.
ACTION:    In `starts_with_word`, accept `c.is_ascii_alphanumeric()` rather than `c.is_ascii_alphabetic()`
           — the Python regex behaviour this faithfully reproduces is the bug, not the contract. Add
           a selftest case planting a binding whose `inventory` is `1.5.5-BEHAVIOUR <anything>` with
           `docs/design/1.5.5-BEHAVIOUR.md` removed from the overlay, proving
           `inventory-ref:file-exists` goes RED. If the digit-leading shape is meant to be skipped,
           delete the alias instead — but then PB-72/PB-92 must class as `Unrecognized`, not be
           dropped.
```

### X-1219 · The conformance `certified` tier is fully declared and never constructed: `cert_id` exists only in prose, `expires` is never compared to a clock, and no fixture ever builds a certified suite — so an expired certification renders a green badge forever
```
CLASS:     missing-code · customer-surface
CERTAINTY: VERIFIED
EVIDENCE:  `cert_id` — the field the §4 hard error is documented to require — is not in the code at all:

             $ git grep -n "cert_id" -- xtask
             render.rs:62:  /// …Requires `cert_id`/`issuer`/`expires` in the verdict.
             render.rs:382: /// …carries no `issuer`/`expires`/`cert_id` … is a HARD ERROR (§4)

           Two doc comments, zero code. `VerdictDoc` (:217-228) has no such field, `read_verdict`
           (:230-267) never reads it, and the §4 guard at :401 tests only
           `v.issuer.is_none() || v.expires.is_none()`. `conformance/verdicts/verdict.schema.json:22`
           documents the field the code does not read.

           `expires` is read and then only copied:

             $ git grep -nE "expire|expiry|SystemTime|now|today" -- xtask/src/gates/conformance_sync/
             render.rs:227,266,401,404,414,415  — parsed from JSON, written into the manifest. That is all.
             CONTROL $ grep -c "SystemTime" xtask/src/gates/changelog.rs  ->  2

           No date comparison exists anywhere in the module, while
           `conformance/manifest.schema.json:52` documents *"For certified entries: past expiry flips
           to not-run(expired)."* That transition does not exist.

           And nothing constructs the tier:

             $ grep -o 'tier = "[a-z-]*"' conformance/registry.toml | sort | uniq -c
                9 tier = "conformant"
                8 tier = "spec-conformant"

           `selftest.rs`'s registry fixtures use only `conformant`/`vendor-blessed`. So
           `Tier::Certified`, `Tier::Capable`, `Tier::EvidenceOnly`, their `claim_for` arms
           (:113-121), their `word()` arms, the EvidenceOnly badge colour `9f9f9f` (:495) and the §4
           hard error are constructed by neither the tree nor any fixture. The highest-stakes rule
           in the gate — *you cannot claim certified without the issued artifact* — has never been
           shown to fire. Also dead: `VerdictDoc::run_id` (:223) is parsed at :262 and read by
           nothing.
ACTION:    (a) Add the expiry transition `assess()` is documented to have: parse `expires` as a date and
           downgrade an armed pass to `not-run("expired")` when it is past, with its own selftest
           case. Inject the clock as a field (the shape `ChangelogGate::today` already uses) or the
           manifest bytes move every run and drift-checking breaks. (b) Either add `cert_id` to
           `VerdictDoc` and to the :401 guard, or strike it from the two doc comments and from
           `verdict.schema.json:22` — three places asserting a field the code does not have.
           (c) Add selftest cases that plant a certified-tier suite: one with issuer+expires
           (proves the Certified arm renders), one without (proves the §4 hard error can fire), one
           past expiry (proves (a)). (d) Drop `run_id`, or emit it as the provenance link the schema
           implies.
```

### X-1222 · `plane-abi-neutrality`'s totality row falls back to comparing two `const`s in its own file whenever the census recognises nothing — the shape its own doc says it was rewritten to eliminate — behind a floor of one over 1,637 files
```
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  The only tree-derived input is a `starts_with(PLANE_GRAMMAR)` scan, taken under a floor of 1:

             $ grep -n 'min_files(1)' xtask/src/gates/plane_abi_neutrality.rs
             222:        .walk(&WalkSpec::new(["crates"]).ext("rs").min_files(1))
             $ find crates -name '*.rs' -not -path '*/target/*' | wc -l
             1637

           `declared_plane_keys` returns `Ok(vec![])` rather than an error when it recognises no
           `pub const PLANE_DECL`, and the consumer then seeds `keys` from the `PLANE_KEYS` const
           and filters it against the `BANNED` const:

             $ python3 -c "PLANE_KEYS=['llm','mcp','a2a','voice']; BANNED=['llm','mcp','a2a','tool',
               'agent','sampling','task','server','card','round','prompt','voice','realtime','audio'];
               m=[k for k in PLANE_KEYS if k not in BANNED]; print(m, 'PASS' if not m else 'FAIL')"
             [] PASS

           That is exactly the state the row's own doc comment says it was rewritten to eliminate:
           *"The totality row used to compare `PLANE_KEYS` with `BANNED` — two `const`s in this
           runner. Two literals agreeing is not a fact about the tree, and no tree could falsify
           it."* A grammar change (`pub static PLANE_DECL`, a macro, a `#[cfg]`-wrapped
           declaration) silently returns the row to that shape, and the existing plant — which
           injects a crate that DOES spell the grammar — cannot catch it.
ACTION:    Give the row a denominator it must clear: make `declared_plane_keys` return `Err` (or have the
           caller emit a named FAIL) when it finds fewer than `PLANE_KEYS.len()` declarations, with a
           sentence naming the grammar it matched on. Raise the walk floor from `min_files(1)` to a
           real one — `min_files(600)`, the `MIN_SOURCES` figure `kind_isolation` already uses over
           the same root. Add a selftest case that blanks the grammar in every declaring file and
           proves the row RED rather than PASS.
```

### X-1206 · `toml_lite::parse_text` has no error path at all and silently DROPS any line matching neither a table header nor `key = value` — and it is the one shared reader with zero cases in `xtask/tests/readers.rs`
```
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  Both entry points return a bare `Document`; there is no error type in the module:

             $ grep -n "pub fn parse\|-> Document\|Result<" xtask/src/toml_lite.rs
             81:pub fn parse(path: &Path) -> Document      (panics on an unreadable FILE — that part is a refusal)
             90:pub fn parse_text(raw: &str) -> Document
             211:    fn parse_str(tag: &str, body: &str) -> Document

           The per-line dispatch tries three shapes and has no `else`:

             $ sed -n '153,200p' xtask/src/toml_lite.rs
                 if trimmed.starts_with("[[") && trimmed.ends_with("]]") { … continue; }
                 if trimmed.starts_with('[')  && trimmed.ends_with(']')  { … continue; }
                 if let Some((key, value)) = trimmed.split_once('=') { … }
                                                                      <-- loop ends; no else

           So a typo'd table header (`[rules.source-denylist` with the `]` lost) matches neither
           bracket arm, carries no `=`, is dropped without a sound, and every key that follows is
           filed under the PREVIOUS table. Its sibling reader over the SAME file does exactly the
           opposite:

             $ grep -n "pub fn parse_str" xtask/src/toml_doc.rs   ->  returns Result<Document,String>,
               Err with a line number on any unrecognized token

           And the file that exists to hold the readers' own cases has none for it:

             $ grep -c "toml_lite" xtask/tests/readers.rs   ->  0
             CONTROL $ grep -c "json_lite" xtask/tests/readers.rs  ->  20

           HOW FAR IT GETS, stated honestly: every caller guards the TOTAL-emptiness case —
           `denylist.rs:174` and `:180` refuse an empty `kinds`/`patterns`
           ("the denylist has nothing to ban, so it can prove nothing"), `full_gate.rs:75` refuses
           an empty skip register, `conformance_sync/render.rs:164` refuses an empty suite list. So
           a wholesale swallow is caught. What is NOT caught, anywhere, is a PARTIAL silent drop —
           a `patterns` list that loses three entries and stays non-empty, or a manifest dependency
           line `workspace_deps.rs:249` never sees. That case has no detector and no test.
ACTION:    Give `parse_text` a `Result`-returning form (or a companion refusal list in the shape
           `manifest.rs::unreadable` already uses) that names (a) any non-blank, non-comment line
           inside a table matching neither a header nor `key = value`, and (b) an array opened with
           `[` that is never closed before EOF or the next table header. Propagate it as a hard
           failure in `denylist.rs`, `full_gate.rs`, `gates/workspace_deps.rs` and
           `gates/conformance_sync/render.rs`. At minimum add the `xtask/tests/readers.rs` case
           proving an unclosed `patterns = [` cannot be read as a truncated list in silence.
```

### X-1207 · `design-bindings:note-witness` refuses a dangling SYMBOL citation and cannot see a dangling FILE PATH — and the very note that motivated the rule carries one: PB-58 cites the deleted `crates/busbar-caps/`
```
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `note_witness_offenders` (`verify.rs:642`) walks `tokens(text)` (`:632`, splitting on anything
           outside `[A-Za-z0-9_]`) and keeps only tokens that are `is_witness_shaped` (`:614`:
           lowercase snake_case, >= 8 chars, >= 3 underscores). A path is shredded by that splitter
           into segments that carry no underscore, so no path can ever be witness-shaped. Replaying
           the exact predicate in python over PB-58's real note text
           (`xtask/src/gates/design_bindings/tables.rs:606`):

             tokens: ['crates','busbar','caps','src','decision','rs','declares','OverBudget', …]
             flagged as witness-shaped: []

           The path it cannot see is dead:

             $ test -d crates/busbar-caps                            -> absent
             CONTROL $ test -e crates/busbar-contract/src/caps/decision.rs -> present
             $ git log --oneline --all -- crates/busbar-caps | tail -1
             be40cf485 busbar-caps: delete the ten stand-ins and name the contract's types

           So the note that motivated this rule's construction — commit `19d894261`,
           *"a note is evidence or it is nothing, and PB-58's witness never existed"* — itself
           carries a SECOND stale citation, of exactly the kind the rule as built cannot detect.
           The module's governing claim (`verify.rs:1-14`) promises both halves; only the
           function-name half is enforced. `check_verdict`'s `lint|gate|script|conformance` arm
           already has the `ctx.root.join(r).exists()` pattern this needs.

           NOT part of this finding: PB-58's SYMBOL half
           (`a_spend_past_the_reservation_is_carried_out_as_an_overdraft`) IS caught and currently
           reds `design-bindings:note-witness` on HEAD. That is the rule working.
ACTION:    In `note_witness_offenders`, add a second scan of `ctx.notes` for bare source-path tokens
           (`\b[\w-]+(?:/[\w.-]+)+\.rs\b`) and check each with `ctx.root.join(path).exists()`,
           refusing any that resolve to nothing — mirroring the existing existence check in
           `check_verdict`. As the immediate data fix, repoint PB-58's note at `tables.rs:606` from
           `crates/busbar-caps/src/decision.rs` to `crates/busbar-contract/src/caps/decision.rs`.
```

### X-1204 · `kernel-token-wire-purity`'s denominator floor is 8 against a scan root of 203 files, and its own comment says "eleven" — 195 files can leave the root and the gate still prints green
```
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  $ sed -n '36,38p' xtask/src/gates/kernel_token_wire_purity.rs
             /// The denominator floor. Eleven production files when this was written; the floor
             /// tracks the real tree rather than `> 0`, because one surviving file is as vacuous as none.
             const SCAN_FLOOR: usize = 8;

             $ find crates/busbar-kernel/src -name '*.rs' | grep -v "/tests/" | grep -v "_tests\.rs" | wc -l
             203
             $ find crates/busbar-kernel/src -name '*.rs' | wc -l
             353

           The comment is off by a factor of eighteen and the floor is 3.9% of the real scan set.
           The row `kernel-token-wire-purity:scan-root` exists precisely because a
           `[ -d "$root" ] || return 0` once let a moved kernel scan nothing and print GREEN — and a
           floor of 8 restores that hole for the migration that is actually happening now: the
           money/usage subtree moving OUT of `crates/busbar-kernel/src`, exactly as `records.rs`
           already moved api -> kernel-ledger -> contract. 195 of 203 files can leave and both rows
           still report clean.

           The offender scan itself is genuinely clean today — all 12 `WIRE_FIELDS` return 0 hits,
           with a working control (`grep -rln tokens_in crates/busbar-kernel/src` -> cost.rs,
           ingress/mod.rs, config/groups.rs) — so the floor is the only thing standing between a
           relocation and a false green.

           SAME SHAPE, LOWER SEVERITY, recorded here rather than as separate rows:
             instance_noun_neutrality.rs:445  min_files(1)  vs 1,611 tracked `crates/**/*.rs`   (X-1209)
             plane_abi_neutrality.rs:222      min_files(1)  vs 1,637                            (X-1222)
             kind_isolation/inputs.rs:755     no floor      vs 105 toml                         (X-1221)
           For contrast, the gates that got this right: `seal_witness.rs:61` and
           `money_invariants.rs:92` both use `SCAN_FLOOR = 200` against ~750 production files, and
           `structure_lint/corpus.rs` uses `CANDIDATE_FLOOR = 200` against 772.
ACTION:    Raise `SCAN_FLOOR` to a measured fraction of today's count (180) and replace the comment with
           the measurement and its date, in the shape `gates::Budget` already uses — "203 production
           files at 2026-09-23 <sha>". If the floor is meant to be a ratchet rather than a number,
           derive it from a committed census the way `inventory_coverage::check_floor` derives its
           per-family totals from `qa/inventory-coverage.json`.
```

### X-1209 · `instance-noun-neutrality:scan-floor` is `min_files(1)` over 1,611 files — a row named for a floor, carrying one
```
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  $ grep -n "min_files" xtask/src/gates/instance_noun_neutrality.rs
             445:        .walk(&WalkSpec::new(["crates"]).ext("rs").min_files(1))
             $ git ls-files 'crates/**/*.rs' | wc -l
             1611

           `ROW_SCAN_FLOOR` is then pushed as an unconditional `Row::pass` whenever `census()`
           returns `Ok` — so the entire defence of this gate's denominator is `min_files(1)`, a bar
           at 0.06% of the real corpus. The selftest proves the row CAN go red, but only via
           `xtask/fixtures/instance-noun-empty/`, whose `crates/` holds a single `keep.txt` and no
           `.rs` at all. A collapse from 1,611 files to 1 passes, and every per-noun row then reports
           `CLEAN` over a corpus of one file.

           Also in this file, recorded under X-1212: `categorize()` at :425-430 names four crates
           that do not exist.
ACTION:    Replace `min_files(1)` with a measured floor (`min_files(1200)`), matching what
           `seal_witness`/`money_invariants` already do over the same tree, and print the count in
           the `ROW_SCAN_FLOOR` pass detail so the denominator is visible on every run rather than
           implied. Keep the `instance-noun-empty` fixture; add a second fixture whose `crates/`
           holds one `.rs` and prove the floor still refuses it.
```

### X-1208 · `money-invariants:single-seal-site` is CRATE-granular while the invariant it holds (#77(2), "never per-plugin") is per-unit — and a per-plane seal site is live inside the allowed crate today
```
CLASS:     money
CERTAINTY: PARK
EVIDENCE:  The two record rules are sound and armed: replaying `token_in_ident` over every field of all
           8 `MONEY_RECORDS` parsed from `crates/busbar-contract/src/records.rs` gives
           `plugin_keyed: []` and `stored_price: []`, with working controls (`plugin` -> True,
           `spend_cents` -> ['spend','cents'], and `priced_from_ms` correctly NOT matching `price`
           because of the segment-boundary rule). All 8 record names still exist (control:
           `grep -c "struct NoSuchRecord" records.rs` -> 0). No `f64`, no unguarded arithmetic, no
           saturation, no ceiling of zero anywhere in this gate.

           The third row is narrower than the claim above it. The module doc states the invariant as
           *"the facts-line constructor is spelled in production only in core/kernel crates, never in
           a plane/plugin crate"*, and the allowlist entry is justified as *"`busbar` is the
           composition root that drives late settlement"*. The test is a crate-prefix match:

             $ sed -n '215p' xtask/src/gates/money_invariants.rs
                 let allowed = SEAL_ALLOWED_ROOTS.iter().any(|root| rel.starts_with(root));

           Classifying every call site in the tree:

             $ git grep -nE 'Posted::settle(_late)?\(' -- crates   (66 TEST, 8 PROD)
             PROD, 2 of them `//!` doc lines (stripped), leaving six:
               crates/busbar-kernel-ledger/src/settle.rs:198
               crates/busbar-kernel/src/recovery.rs:99
               crates/busbar-kernel/src/teller.rs:1222, :1344
               crates/busbar-kernel/src/tick.rs:320
               crates/busbar/src/root/units_llm.rs:875     <-- the LLM PLANE's unit module

           `crates/busbar/src/root/units_llm.rs` is production (`#[cfg(test)]` does not begin until
           :1940) and is declared `pub mod units_llm` at `crates/busbar/src/root/mod.rs:90`. It
           starts with `crates/busbar/`, so the prefix admits it. In substance that is a per-plane
           seal, and #77(2) says one sealed FACTS line per unit, never per-plugin.

           Related, and part of the same ruling: nothing in this gate checks that a seal EXISTS on
           any unit path, nor that there is ONE per unit — only that none appears outside five
           crate roots. And detection is `code.contains("Posted::settle(")`, so
           `use …::Posted as P; P::settle(` in a plane crate would pass.
ACTION:    OWNER RULING NEEDED — this is a money invariant and the row currently reads green.
           Decide one of: (1) #77(2) is crate-granular, in which case rename the row to what it
           measures (`no-plugin-side-seal`) and strike "seal one facts-line per unit" from the
           registry summary at `gates/mod.rs:2471-2474`; or (2) it is per-unit, in which case
           `crates/busbar/src/root/units_*.rs` must be excluded from `SEAL_ALLOWED_ROOTS` and
           `units_llm.rs:875` becomes a tracked debt row. Either way, add a row that COUNTS seal
           sites and refuses a count of zero (the floor posture `SCAN_FLOOR` already takes for the
           walk), and match on the type plus the method rather than the literal call string.
```

### X-1205 · `map-proof` is a registered gate that no workflow names and that the excuse table which exists to catch exactly this does not carry
```
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:  `full_gate::gate_set_diff` reconciles the registry against `ci.yml` and requires every
           registered gate to be either invoked there or carry a CHECKED entry in
           `REGISTRY_NOT_IN_CI`. Computing both sides:

             $ grep -n "map-proof\|sweep-coverage\|unconstructed" .github/workflows/ci.yml
             (no output)
             CONTROL $ grep -n "design-bindings" .github/workflows/ci.yml  ->  :3669, :3678, :3680

             $ python3  # registry - ci.yml names - REGISTRY_NOT_IN_CI
             ci.yml gate names (38): [audit-ledger … workspace-deps]
             REGISTERED BUT ABSENT (3): ['map-proof', 'sweep-coverage', 'unconstructed']
             INVOKED BUT UNREGISTERED: []

           (`REGISTRY_NOT_IN_CI` was extracted with a python regex after a `grep -oE '^\s{4}"…"'`
           attempt returned EMPTY — `\s` is not POSIX ERE. The control `grep -x denylist` on the
           corrected list confirms the extraction.)

           `full_gate.rs:978-988` asserts `diff.registered_but_absent.is_empty()` with the message
           *"a gate nothing runs is a gate that cannot fail"*, and `ci.yml:454` runs
           `cargo xtask full-gate --selftest` with no `continue-on-error`. So the reconciliation is
           doing its job and that CI step is red about these three today.

           `map-proof` is `Tier::Full` and IS reached by `cargo xtask gate --all`, but the only
           workflow running `--all` is `.github/workflows/manual-keep-proof.yml` (:529) — a manual
           one. Both `map-proof` (`3a3e7ab00`) and `sweep-coverage` (`adc5f599c`) are very recent, so
           this is almost certainly in-flight rather than rot; it is recorded because the row is
           real and the fix is a two-line choice, not because the instrument failed.
           (`sweep-coverage` and `unconstructed` are outside this slice — named, not acted on.)
ACTION:    Pick one, in the same commit: add a `cargo xtask gate map-proof` step to `ci.yml` (it is
           `Tier::Full`, so the full-tier job), or add a `REGISTRY_NOT_IN_CI` entry whose `Excuse`
           names the route that really covers it — `Excuse::ReleaseScript` if
           `scripts/verify-1.6.0-done.sh` is meant to own it, which today it does not.
```

### X-1210 · `no-self-filed-issues` reads `.github/workflows` only; `.github/actions` and `.github/scripts` exist, carry the same `run:` shell it hunts, and are never scanned
```
CLASS:     instrument-blind
CERTAINTY: ADJUDICATE
EVIDENCE:  $ grep -n "const WF_DIR" xtask/src/gates/no_self_filed_issues.rs
             43:const WF_DIR: &str = ".github/workflows";
           and :276-285 additionally drops any path carrying a further `/` under it ("a nested file
           the shell never saw").

             $ ls -d .github/*/
             .github/actions/  .github/ISSUE_TEMPLATE/  .github/scripts/  .github/workflows/
             $ ls .github/actions ; ls .github/scripts
             cargo-home
             bump_cargo.py  roll_changelog.py

           A composite action's `action.yml` carries `runs.steps[].run:` — the same shell the gate
           hunts — and is invoked by workflows, but lives one directory down and is never read.

           Today this is a scope gap and not a miss:
             $ grep -rnE "gh +issue +(create|edit|close|comment|reopen)|issues\.(create|update|createComment)" \
                 .github/actions .github/scripts scripts/
             (no output)
             CONTROL — the same ERE over .github/workflows returns the three known COMMENT lines at
             release.yml:1167, plugin-consumer-verify.yml:457, verify-deploy.yml:256

           Claim (B), `issues: write`, is no backstop: the module doc already records that a PAT
           from `secrets.*` never consults `permissions:`. Marked ADJUDICATE because the gap is
           proven but nothing exploits it today. `DISCOVERY_FLOOR = 5` against 28 workflow files is
           fine.
ACTION:    Widen the walk to `.github` with a `yml|yaml` ext filter (keeping the depth-1 workflow rule
           for the discovery floor only), or add `.github/actions/**/action.yml` and
           `.github/scripts` as a second scanned root. Add one selftest plant putting the built
           `gh issue create` string into `.github/actions/planted/action.yml`.
```

### X-1216 · `denylist --selftest`'s GREEN cases have no positive control that the closure walk ran — `run_on` treats "package not found in cargo metadata" as a warning and a skip
```
CLASS:     instrument-blind
CERTAINTY: ADJUDICATE
EVIDENCE:  `check()` with an empty `expect_offenders` asserts one thing:

             $ sed -n '92,96p' xtask/src/selftest.rs
                 if expect_offenders.is_empty() {
                     if hits.is_empty() { println!("  GREEN  {label}: 0 hits, as expected"); }

           and the producer degrades silently when metadata cannot resolve the fixture:

             $ sed -n '1226,1234p' xtask/src/denylist.rs
                 } else {
                     eprintln!("xtask denylist: warning: {} not found in `cargo metadata` output; skipped", pc.name);
                 }

           So a GREEN case cannot distinguish "the transitive closure was walked and was clean" from
           "the closure was never walked". The fixtures resolve `libc = "0.2"` from the registry, so
           an offline or cache-cold run is exactly the condition that produces it.

           MITIGATING, and the reason this is ADJUDICATE rather than VERIFIED-severe: the RED cases
           DO fail closed — `dirty-dep` expecting `libc` reports "missing offenders" and the battery
           returns non-zero. So a dead metadata run is caught by the suite as a whole; what is lost
           is the per-case meaning of every green.
ACTION:    Give `check()` a denominator: have `denylist::run_on` return the number of closure nodes it
           walked (or a `Result`), and require a GREEN case to assert `walked > 0` alongside
           `hits.is_empty()`. Turn the `eprintln!` skip into a hard error in the selftest path — a
           fixture whose package cannot be resolved is a broken fixture, not a clean one.
```

### X-1211 · The floor comments no longer describe the tree: `workspace-deps` claims "63 members, 62 manifests" against a measured 49 and 49, and `MIN_MEMBERS` is 8
```
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  $ sed -n '66,72p' xtask/src/gates/workspace_deps.rs
             /// Floors. Deliberately well under today's counts (63 members, ~200 inherited
             /// declarations, 62 manifests under `crates/`) …
             pub const MIN_MEMBERS: usize = 8;
             pub const MIN_INHERITED: usize = 40;
             pub const MIN_CRATE_MANIFESTS: usize = 40;

             $ awk '/^members = \[/,/^\]/' Cargo.toml | grep -c '"crates/'   ->  49
             $ find crates -maxdepth 2 -name Cargo.toml | wc -l               ->  49
             CONTROL — the same counting method over xtask/fixtures/ (not members) -> 0

           The advertised cushion does not exist: the comment promises 22-23 crates of slack and the
           real margin is 9. Both floors still clear today (49 > 40), so the gate is not blind — but
           the tree is actively CONSOLIDATING (busbar-core into busbar-kernel, busbar-caps into
           busbar-contract), which moves this number the wrong way, and `MIN_MEMBERS = 8` against 49
           would let a discovery bug lose 41 of 49 members and still pass.

           Same shape in the sibling gate: `package_selectors.rs:114 UNIVERSE_FLOOR = 40` against 51
           workspace packages — 11 of slack, from a comment written when there were more.
ACTION:    Re-measure and restate both comments with the count AND the date, the way `gates::Budget`
           already does, and raise `MIN_MEMBERS` from 8 to a real fraction of 49. If the
           consolidation is expected to continue, derive the floor from the committed member list
           rather than from a hand-written number that nobody re-reads.
```

### X-1220 · `ci-umbrella`'s TIER rule proves only the harmless arm — the arm that forgives a genuinely skipped required job has no red case
```
CLASS:     instrument-blind
CERTAINTY: ADJUDICATE
EVIDENCE:  $ grep -n "ROW_TIER" xtask/src/gates/ci_umbrella.rs
             44 (doc) · 77 (const) · 317 (the ONE selftest case) · 537,551 (OWED) · 992,999 (probe)

           The single case at :310-319 plants `windows|full|` -> `windows|fast|`, driving
           `rule_tier`'s `("fast", true)` arm at :982-985. Its twin `("full", false)` at :978-981 —
           an UNGUARDED job scored `full`, which the module doc at :48-50 names as "the required
           check quietly not requiring it", because the umbrella then forgives that job's real
           `skipped` — has no case anywhere. The framework's coverage demand is per ROW id, not per
           ARM, so `verify_report` is satisfied by the case that exists.

           The arm is reachable in this tree: `proof-manifest`
           (`if: github.event_name == 'push' && contains(...)`) and `llm-conformance`
           (`if: ${{ !cancelled() }}`) both yield `is_full_tier_guarded == false`, so labelling
           either `full` in RESULTS would fire it. ADJUDICATE: read from the source and the grep
           above, not from a run of the gate.

           Everything else in this gate measured live and healthy: every selftest anchor string is
           still present in ci.yml (COUNT=1 each), and a python reconciliation gives 32 jobs /
           28 needs / 28 RESULTS with 0 membership offenders against floors of 20/15/15.
ACTION:    Add one case beside :310 using an existing unguarded job — `plant_subst
           "llm-conformance|fast|${{ needs.llm-conformance.result }}" ->
           "llm-conformance|full|${{ needs.llm-conformance.result }}"`, covering `&[ROW_TIER]` and
           naming `["llm-conformance", "carries no full-tier guard"]`.
```

### X-1223 · `Freeze::sites` is computed on every run of the plane-purity freeze witness and read by nothing
```
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  $ git grep -n "\.sites" -- xtask/src/
             xtask/src/gates/plane_purity/freeze.rs:119:            out.sites.push(site);

           One hit in the whole crate: a write with no reader.

             CONTROL — the sibling field that IS read:
             $ git grep -n "uprefs" -- xtask/src/
             freeze.rs:88 (decl) · freeze.rs:117 (write) · plane_purity/mod.rs:275 (read, in the
             row detail `format!("count={} defs={} uprefs={}"…)`) · mod.rs:684,697,700,712

           The consumer `plane_purity::mod.rs::freeze_row` prints `count`/`defs`/`uprefs` only, and
           the plant at `mod.rs:569-574` comments that a named site "would be a row the legacy half
           cannot produce" — so the list was deliberately withheld to stay at parity with a script
           that has since been deleted (`scripts/g6-freeze-witness.sh`, removed at `4b11e2f19`).
           The declared capability at `freeze.rs:82-83` ("Every remaining site, `file:line`, in walk
           order") does not ship.

           Related, same struct, not raised separately: `defs` is read but structurally pinned at
           zero — `DEFS_PREFIX` is `crates/busbar-kernel/src/ir/`, which exists but holds only the
           neutral surface `TYPES` deliberately excludes, so a python replay of `measure()` over
           `crates/busbar-kernel/src` gives `total: 0  defs: 0  uprefs: 0` and the defs/uprefs split
           the module header calls "the whole diagnostic value" can no longer take two values.
ACTION:    Surface it or delete it — do not leave it computed and discarded. The constraint that
           justified withholding it (byte parity with a shell that no longer exists) is gone with
           X-1201, so the better fix is to add the site list to the FAIL branch of `freeze_row`,
           where a reader would use it.
```

### X-1213 · `design_bindings.rs`'s doc says `REGEN-CLEAN` is "owed only under `--strict`"; the code owes it unconditionally, and `ci.yml` agrees with the code
```
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  $ sed -n '187,189p' xtask/src/gates/design_bindings.rs
             /// It is owed only under `--strict`, because plain `--check` is the gap REPORT and a
             /// report on a slightly stale ledger is still a useful report.

           The code has no such branch:

             $ sed -n '200,210p;241,242p' xtask/src/gates/design_bindings.rs
                 ids.push(ROW_REGEN.to_string());
                 ids.push(ROW_NOTE_WITNESS.to_string());          # owed(), unconditional
                 rows.push(regen_row(cx, &inputs));
                 rows.push(note_witness_row(&inputs.ctx));        # run(), unconditional

           `DesignBindingsGate` is a unit struct — there is no `strict` field to condition on — and
           `cli.rs:380-384` shows `--strict` only swaps `execute` for `execute_strict`, whose sole
           difference (`gates/mod.rs:1510-1514` vs `:1736-1739`) is whether `Reconcile` honours
           `gate.skip_allow()`. It never touches which rows are owed.

           `ci.yml:3660-3666` describes the row the way the CODE behaves — "it is now the owed
           ledger row `design-bindings:regen-clean`, reconciled with every other row" — with no
           `--strict` qualifier, and the plain step at `ci.yml:3680` is exactly the run the stale
           comment says is unconditional. Two of the three descriptions agree; only the module's own
           doc is wrong.
ACTION:    Fix the comments at :20-22 and :187-189 to say that `design-bindings:regen-clean` and
           `:note-witness` are unconditionally owed and judged in both modes, and that `--strict`
           differs only in refusing the named-gap `skip_allow` list. No code change: unconditional
           enforcement is the safer behaviour, since a stale ledger hides an added binding in either
           mode.
```

### X-1212 · `instance-noun-neutrality`'s `categorize()` sorts leaks into buckets named for four crates that do not exist
```
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  $ sed -n '425,430p' xtask/src/gates/instance_noun_neutrality.rs
                 "busbar-substrate" | "busbar-substrate-values" => ("substrate", …),
                 "api" | "busbar-contract" | "busbar-contract-transport" | "busbar-caps"
                 | "busbar-grammar" => ("shared-crate", …),

             $ for n in busbar-substrate busbar-contract-transport busbar-caps busbar-grammar; do
                 [ -d "crates/$n" ] && echo "PRESENT $n" || echo "ABSENT  $n"; done
             ABSENT (all four)
             CONTROL — the live names in the same arms:
             busbar-substrate-values PRESENT · api PRESENT · busbar-contract PRESENT

           Four dead match arms. Severity is low and stated plainly: `categorize` only chooses a
           LABEL and an owning wave, and the `_ => ("core", …)` fallthrough still fires, so no leak
           escapes detection. It is drift in a table a human reads, not a blind rule.

           Checked and clean in the same file: all 17 `FAM_*` family lists name only crates that
           exist, and both `GCP_GENERIC_MENTION_FILES` exemption paths resolve — so the parts of this
           gate that CAN change a verdict are not drifted.
ACTION:    Strike `busbar-substrate`, `busbar-contract-transport`, `busbar-caps` and `busbar-grammar`
           from the two match arms. Fold this into the X-1211 pass so the dead-name sweep over
           `xtask/` happens once.
```

### X-1215 · `xtask/tests/infra.rs` cites `crates/busbar-core/...` as "the live instance" of the shape it tests; that crate was deleted into `busbar-kernel`
```
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  $ sed -n '318,330p' xtask/tests/infra.rs
             // The live instance: crates/busbar-core/src/admin/v1/contract/taxonomy.rs:610, inside a
             // `#[cfg(any(test, …))]` item.

             $ ls crates | grep -cx busbar-core   ->  0
             $ git log --oneline --diff-filter=D --summary -- 'crates/busbar-core/*' | head -1
             673ecdaaa W4.a: absorb busbar-core INTO busbar-kernel; delete busbar-core (#19/#37)
             $ test -e crates/busbar-kernel/src/admin/v1/contract/taxonomy.rs   ->  present

           A comment only — the test's own fixture is a self-contained synthetic string, so the
           scanner's behaviour is unaffected — but it is a path named here that no longer exists,
           and it will send the next reader looking for "the live instance" in a deleted crate.
ACTION:    Repoint the comment at `crates/busbar-kernel/src/admin/v1/contract/taxonomy.rs`. Fold into the
           same dead-name pass as X-1211/X-1212.
```

### X-1214 · `structure_lint/roots.rs` carries a `busbar-proto-*` crate prefix that matches nothing in this tree
```
CLASS:     drift
CERTAINTY: PARK
EVIDENCE:  $ sed -n '58,62p' xtask/src/gates/structure_lint/roots.rs   (`proto_root_of`)
             …crate_name.starts_with("busbar-proto-") || …busbar-llm… || …busbar-mcp… || …-codec…
             $ ls crates | grep -c '^busbar-proto-'   ->  0
             CONTROL $ ls crates | grep -c '^busbar-llm'  ->  2

           The dead prefix is OR'd with three live alternatives (`busbar-llm`, `busbar-mcp`,
           `*-codec`, all populated), so `ROW_PROTO_ROOTS` is armed today and this is a dead
           disjunct rather than a blind rule. The same prefix is duplicated at `selftest.rs:130`
           when building the "empty every protocol crate" plant, which makes it look deliberate —
           the doc calls it "the older per-protocol naming". PARK rather than raise: whether this is
           forward-compatibility scaffolding or rot is an owner's call, not a reader's.
ACTION:    If `busbar-proto-*` is permanently retired, drop the disjunct from `proto_root_of` and the
           matching branch in `selftest.rs:130`, so the rule stops carrying a condition nothing can
           hit. Otherwise leave it and say in the comment which it is.
```

### CITED, NOT RAISED — the existing row X-63

`xtask/src/gates/reachability.rs` reds nothing when a roster plane's `root/units_*.rs` is simply
ABSENT: `unit-path` and `root-reach` both score `Ok(...)` on the `None` arm (`:1244`, `:1297`),
so `decision` — which has no `crates/busbar/src/root/units_decision.rs` — passes 2 of 3 axes for
free, scoring strictly better than mcp/a2a/streaming whose modules exist but are unreached. I
re-verified it independently and found one detail worth adding to the existing row: the
`FIX_RED` fixture's own `root/mod.rs` DECLARES `pub mod units_decision`, so the absent-module
shape is not merely unplanted — the fixture tree makes it unplantable without a new fixture.
This is **already on `docs/design/1.6.0-THE-LIST.md:271` as X-63, VERIFIED**. Not re-raised.

## TALLY
```
files in slice:  164
verdict lines:   164
CLEAN:           130
FINDING:         33      rows raised: 24   (X-1200 .. X-1223, contiguous)
DELETABLE:       1
UNREADABLE:      0

by class:      instrument-blind 14 · drift 5 · missing-code 4 · customer-surface 2 · money 1 · config 1
               (rows carrying two classes are counted under both; 24 distinct rows)
by certainty:  VERIFIED 19 · ADJUDICATE 3 · PARK 2
```

## WHAT THIS SLICE PROVES ABOUT FILES OUTSIDE IT (said, not acted on)

- `xtask/src/full_gate.rs` — `gate_set_diff` is RED on HEAD about `map-proof`, `sweep-coverage`
  and `unconstructed` (X-1205). Two of the three are outside this slice. The instrument is
  working; the entries are missing.
- `crates/busbar-kernel/benches/plane_host_vtable_{perf,alloc}.rs` — both headers document
  `cargo bench -p busbar-core`, a package that no longer exists (X-1202).
- `crates/busbar/src/root/units_llm.rs:875` — a production per-plane `Posted::settle_late` site
  that `money-invariants` admits today (X-1208). PARKed for an owner ruling.
- `xtask/src/gates/plane_purity/mod.rs:585` declares
  `legacy_companions() -> vec![vec!["scripts/g6-freeze-witness.sh"]]`; that script was deleted at
  `4b11e2f19`. Same shape as X-1201, in a file another slice owns.
- `xtask/src/gates/plane_purity/mod.rs:80` carries `CORE_FLOOR: usize = 1` — the X-1204 floor
  shape, in a file another slice owns.
- `xtask/src/parity.rs` (669 lines) is the harness for the subsystem X-1201 shows is unreachable.
- `conformance/verdicts/*.json`, `conformance/manifest.schema.json:52` and `README.md:30-41` are
  the data and the customer surface behind X-1217 and X-1219. Not touched: the oracle is never
  waived and a badge is a billed claim.

## WHAT WAS CHECKED AND HELD

The harness's own spine is sound, and the negative results are worth recording because they are
where this defect class would have been cheapest to find:

- `Ctx::list` returns `WalkError::MissingRoot` for a scan root that does not exist, so the
  "gate scans a dissolved crate" failure is structurally caught at the reader — every dead-crate
  path literal in this slice turned out to be an `Overlay` plant, not a live root.
- `Gate::owed` + `Reconcile` are red in BOTH directions, so a rule that stops emitting its row is
  DID NOT RUN rather than silence; `Expect::Inert` and `Expect::Impossible` mean a plant that
  changed nothing, or a row already red before the plant, is never scored as a pass.
- `DEFAULT_BASELINE_REF` is `v1.5.3` and `git rev-parse --verify v1.5.3` resolves — the HEAD-vs-HEAD
  defect was genuinely repaired in `c1a73fc0f`.
- `map_proof`'s `ROW_FLOORED` (added in `80601a28c`) does name both zero-floor corpus documents,
  and its per-document `reproduces` rows refuse vacuity explicitly.
- `sha256.rs` was transcribed into python and matched `hashlib` on four vectors including the
  64-byte block boundary and 1e6x'a'.
- `loc.rs:716` hard-fails on a parse error rather than counting zero lines — the one failure that
  would have silently lowered every ceiling in the tree.
- `xtask/tests/gate_mutation_proof.rs`'s env gate is real: `gate-mutants.yml:186` sets it and :192
  runs it, in a required check.
- All 88 fixture files are reachable from a fixture root some selftest names, and the subjects the
  denylist fixtures plant against (`libc`, `async_std`, `std::fs`, `std::env`) are all still on
  `qa/construction.toml`'s banned lists.
