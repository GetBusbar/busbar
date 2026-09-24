# S01-kernel-a — sweep verdicts

Slice: `/Users/matthew/Developer/GetBusbar/.sweep/S01-kernel-a.txt` — **154 files**, the first half
of `crates/busbar-kernel`, the thin engine.
X-id block: **X-1000 .. X-1099**. No id outside it is used.

**Reachability was measured once, for the whole slice**, by parsing every `mod` and `#[path] mod`
declaration under `crates/busbar-kernel/src` (1,807 `.rs` files walked) and matching each slice path
against the result: **`UNREACHED: 0`**. Positive control: the same walk given a synthetic path
`src/NOPE.rs` reports it unreached. Every file below is compiled.

**The plane-noun scan** strips Rust comments (a real brace-tracking stripper, not a line prefix
test) and then matches the `plane-purity` scanner's own alternations —
`xtask/src/gates/plane_purity/scanner.rs:29` (`llm|mcp|a2a|voice`), `:44` (the six dialects), `:65`
and `:76` (the CamelCase and SCREAMING prefixes). Positive control: the same scan over
`src/config/tests/tests.rs` returns 4 hits, so every zero in the table is a measurement.
**Result: 3 plane-named code lines in the 83 production files (all in `src/config/mod.rs`), 311 in
test scope.**

**The deleted-crate scan** counts `busbar[-_]core`, `busbar[-_]substrate`, `busbar[-_]caps`,
`busbar[-_]grammar`, `busbar[-_]admin` and `busbar-unit-`, with the LIVE spellings
`busbar-core-{admin,connsec,oauth2}` and `busbar-substrate-values` subtracted first. Positive
control: `ls -d crates/busbar-kernel` resolves where `ls -d crates/busbar-core` does not.

| FILE | VERDICT | EVIDENCE | ROWS |
|---|---|---|---|
| `crates/busbar-kernel/benches/plane_host_vtable_alloc.rs` | FINDING | `grep -n "\[\[bench\]\]" -A2 crates/busbar-kernel/Cargo.toml` -> registered, harness=false; 171 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1007, X-1004 |
| `crates/busbar-kernel/benches/pool_upstream_creds.rs` | FINDING | `grep -n "\[\[bench\]\]" -A2 crates/busbar-kernel/Cargo.toml` -> registered, harness=false; 116 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | X-1006 |
| `crates/busbar-kernel/src/admin_verbs.rs` | CLEAN | `grep -nE "^\s*(pub )?mod admin_verbs;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 302 lines; plane-noun scan (comment-stripped): 0 code / 5 incl. comments | - |
| `crates/busbar-kernel/src/admin_witness.rs` | FINDING | `grep -nE "^\s*(pub )?mod admin_witness;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 46 lines; plane-noun scan (comment-stripped): 0 code / 2 incl. comments; deleted-crate names: 9 | X-1008, X-1004 |
| `crates/busbar-kernel/src/admin/mod.rs` | FINDING | `grep -nE "^\s*(pub )?mod admin;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 44 lines; plane-noun scan (comment-stripped): 0 code / 4 incl. comments; deleted-crate names: 6 | X-1004 |
| `crates/busbar-kernel/src/admin/planeverbs.rs` | CLEAN | `grep -nE "^\s*(pub )?mod planeverbs;" crates/busbar-kernel/src/admin/mod.rs` -> 1 hit; 148 lines; plane-noun scan (comment-stripped): 0 code / 2 incl. comments | - |
| `crates/busbar-kernel/src/admin/seam.rs` | FINDING | `grep -nE "^\s*(pub )?mod seam;" crates/busbar-kernel/src/admin/mod.rs` -> 1 hit; 50 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 13 | X-1004 |
| `crates/busbar-kernel/src/admin/tests/planeverbs_tests.rs` | FINDING | `grep -n "path.*planeverbs_tests.rs" crates/busbar-kernel/src/admin/planeverbs.rs` -> 1 hit; 89 lines; 3 `#[test]`, 4 `assert`; plane-noun scan (comment-stripped): 3 code / 8 incl. comments | X-1013 |
| `crates/busbar-kernel/src/admin/tests/versions_tests.rs` | FINDING | `grep -n "path.*versions_tests.rs" crates/busbar-kernel/src/admin/versions.rs` -> 1 hit; 51 lines; 1 `#[test]`, 9 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/admin/v1/contract/mod.rs` | CLEAN | `grep -nE "^\s*(pub )?mod contract;" crates/busbar-kernel/src/admin/v1/mod.rs` -> 1 hit; 1078 lines; plane-noun scan (comment-stripped): 0 code / 3 incl. comments | - |
| `crates/busbar-kernel/src/admin/v1/contract/taxonomy.rs` | FINDING | `grep -nE "^\s*(pub )?mod taxonomy;" crates/busbar-kernel/src/admin/v1/contract/mod.rs` -> 1 hit; 805 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 3 | X-1008, X-1004 |
| `crates/busbar-kernel/src/admin/v1/contract/tests/cursor_tests.rs` | CLEAN | `grep -n "path.*cursor_tests.rs" crates/busbar-kernel/src/admin/v1/contract/mod.rs` -> 1 hit; 20 lines; 1 `#[test]`, 7 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/admin/v1/contract/tests/tests.rs` | CLEAN | `grep -n "path.*tests.rs" crates/busbar-kernel/src/admin/v1/contract/mod.rs` -> 1 hit; 199 lines; 7 `#[test]`, 34 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/admin/v1/json/mod.rs` | FINDING | `grep -nE "^\s*(pub )?mod json;" crates/busbar-kernel/src/admin/v1/mod.rs` -> 1 hit; 71 lines; plane-noun scan (comment-stripped): 0 code / 1 incl. comments; deleted-crate names: 3 | X-1004 |
| `crates/busbar-kernel/src/admin/v1/mod.rs` | FINDING | `grep -nE "^\s*(pub )?mod v1;" crates/busbar-kernel/src/admin/mod.rs` -> 1 hit; 16 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 2 | X-1004 |
| `crates/busbar-kernel/src/admin/versions.rs` | CLEAN | `grep -nE "^\s*(pub )?mod versions;" crates/busbar-kernel/src/admin/mod.rs` -> 1 hit; 108 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/api.rs` | FINDING | `grep -nE "^\s*(pub )?mod api;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 176 lines; plane-noun scan (comment-stripped): 0 code / 1 incl. comments; deleted-crate names: 2 | X-1004 |
| `crates/busbar-kernel/src/audit_ring.rs` | FINDING | `grep -nE "^\s*(pub )?mod audit_ring;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 377 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | X-1009 |
| `crates/busbar-kernel/src/audit/mod.rs` | CLEAN | `grep -nE "^\s*(pub )?mod audit;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 569 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/audit/tests/boot_verify_golden.rs` | FINDING | `grep -n "path.*boot_verify_golden.rs" crates/busbar-kernel/src/audit/mod.rs` -> 1 hit; 261 lines; 2 `#[test]`, 13 `assert`; plane-noun scan (comment-stripped): 8 code / 13 incl. comments | X-1013 |
| `crates/busbar-kernel/src/audit/tests/chain_tests.rs` | FINDING | `grep -n "path.*chain_tests.rs" crates/busbar-kernel/src/audit/mod.rs` -> 1 hit; 600 lines; 18 `#[test]`, 52 `assert`; plane-noun scan (comment-stripped): 2 code / 5 incl. comments; deleted-crate names: 1 | X-1004, X-1013 |
| `crates/busbar-kernel/src/auth_cache.rs` | CLEAN | `grep -nE "^\s*(pub )?mod auth_cache;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 232 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/auth/audience.rs` | CLEAN | `grep -nE "^\s*(pub )?mod audience;" crates/busbar-kernel/src/auth/mod.rs` -> 1 hit; 104 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/auth/exchange.rs` | FINDING | `grep -nE "^\s*(pub )?mod exchange;" crates/busbar-kernel/src/auth/mod.rs` -> 1 hit; 144 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | X-1001 |
| `crates/busbar-kernel/src/auth/self_keys.rs` | FINDING | `grep -nE "^\s*(pub )?mod self_keys;" crates/busbar-kernel/src/auth/mod.rs` -> 1 hit; 411 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | X-1001 |
| `crates/busbar-kernel/src/auth/tests/audience_tests.rs` | FINDING | `grep -n "path.*audience_tests.rs" crates/busbar-kernel/src/auth/audience.rs` -> 1 hit; 134 lines; 5 `#[test]`, 6 `assert`; plane-noun scan (comment-stripped): 6 code / 6 incl. comments | X-1013 |
| `crates/busbar-kernel/src/auth/tests/exchange_tests.rs` | FINDING | `grep -n "path.*exchange_tests.rs" crates/busbar-kernel/src/auth/exchange.rs` -> 1 hit; 28 lines; 1 `#[test]`, 6 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/auth/tests/self_keys_tests.rs` | CLEAN | `grep -n "path.*self_keys_tests.rs" crates/busbar-kernel/src/auth/self_keys.rs` -> 1 hit; 725 lines; 21 `#[test]`, 57 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/auth/tests/tests.rs` | FINDING | `grep -n "path.*tests.rs" crates/busbar-kernel/src/auth/mod.rs` -> 1 hit; 2755 lines; 68 `#[test]`, 222 `assert`; plane-noun scan (comment-stripped): 111 code / 163 incl. comments | X-1013 |
| `crates/busbar-kernel/src/auth/tests/token_tests.rs` | CLEAN | `grep -n "path.*token_tests.rs" crates/busbar-kernel/src/auth/token.rs` -> 1 hit; 1714 lines; 36 `#[test]`, 129 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/billing.rs` | FINDING | `grep -nE "^\s*(pub )?mod billing;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 21 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 2 | X-1004 |
| `crates/busbar-kernel/src/boot.rs` | CLEAN | `grep -nE "^\s*(pub )?mod boot;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 137 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/catalogue.rs` | FINDING | `grep -nE "^\s*(pub )?mod catalogue;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 207 lines; plane-noun scan (comment-stripped): 0 code / 7 incl. comments; deleted-crate names: 2 | X-1004 |
| `crates/busbar-kernel/src/config_validate/secret_refs.rs` | CLEAN | `grep -nE "^\s*(pub )?mod secret_refs;" crates/busbar-kernel/src/config_validate/mod.rs` -> 1 hit; 481 lines; plane-noun scan (comment-stripped): 0 code / 1 incl. comments | - |
| `crates/busbar-kernel/src/config_validate/tests/secret_ref_coverage.rs` | FINDING | `grep -n "path.*secret_ref_coverage.rs" crates/busbar-kernel/src/config_validate/secret_refs.rs` -> 1 hit; 643 lines; 7 `#[test]`, 26 `assert`; plane-noun scan (comment-stripped): 8 code / 10 incl. comments; deleted-crate names: 1 | X-1004, X-1013 |
| `crates/busbar-kernel/src/config_validate/tests/tests.rs` | FINDING | `grep -n "path.*tests.rs" crates/busbar-kernel/src/config_validate/mod.rs` -> 1 hit; 5744 lines; 162 `#[test]`, 368 `assert`; plane-noun scan (comment-stripped): 83 code / 91 incl. comments | X-1013 |
| `crates/busbar-kernel/src/config/auth.rs` | FINDING | `grep -nE "^\s*(pub )?mod auth;" crates/busbar-kernel/src/config/mod.rs` -> 1 hit; 474 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 4 | X-1000, X-1004 |
| `crates/busbar-kernel/src/config/groups.rs` | FINDING | `grep -nE "^\s*(pub )?mod groups;" crates/busbar-kernel/src/config/mod.rs` -> 1 hit; 565 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/config/hooks.rs` | FINDING | `grep -nE "^\s*(pub )?mod hooks;" crates/busbar-kernel/src/config/mod.rs` -> 1 hit; 582 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 3 | X-1004 |
| `crates/busbar-kernel/src/config/limits.rs` | FINDING | `grep -nE "^\s*(pub )?mod limits;" crates/busbar-kernel/src/config/mod.rs` -> 1 hit; 681 lines; 1 `#[test]`, 3 `assert`; plane-noun scan (comment-stripped): 0 code / 4 incl. comments; deleted-crate names: 13 | X-1004 |
| `crates/busbar-kernel/src/config/migrate_export.rs` | CLEAN | `grep -nE "^\s*(pub )?mod migrate_export;" crates/busbar-kernel/src/config/mod.rs` -> 1 hit; 263 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/config/migrate.rs` | CLEAN | `grep -nE "^\s*(pub )?mod migrate;" crates/busbar-kernel/src/config/mod.rs` -> 1 hit; 2570 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/config/mod.rs` | FINDING | `grep -nE "^\s*(pub )?mod config;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 2823 lines; plane-noun scan (comment-stripped): 3 code / 25 incl. comments; deleted-crate names: 4 | X-1002, X-1003, X-1004 |
| `crates/busbar-kernel/src/config/overlay.rs` | CLEAN | `grep -nE "^\s*(pub )?mod overlay;" crates/busbar-kernel/src/config/mod.rs` -> 1 hit; 1276 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/config/parse.rs` | FINDING | `grep -nE "^\s*(pub )?mod parse;" crates/busbar-kernel/src/config/mod.rs` -> 1 hit; 55 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 3 | X-1004 |
| `crates/busbar-kernel/src/config/patch.rs` | CLEAN | `grep -nE "^\s*(pub )?mod patch;" crates/busbar-kernel/src/config/mod.rs` -> 1 hit; 194 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/config/pools.rs` | FINDING | `grep -nE "^\s*(pub )?mod pools;" crates/busbar-kernel/src/config/mod.rs` -> 1 hit; 618 lines; plane-noun scan (comment-stripped): 0 code / 2 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/config/secret.rs` | CLEAN | `grep -nE "^\s*(pub )?mod secret;" crates/busbar-kernel/src/config/mod.rs` -> 1 hit; 285 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/config/tests/config_backcompat_corpus.rs` | FINDING | `grep -n "path.*config_backcompat_corpus.rs" crates/busbar-kernel/src/config/mod.rs` -> 1 hit; 285 lines; 1 `#[test]`, 4 `assert`; plane-noun scan (comment-stripped): 1 code / 1 incl. comments; deleted-crate names: 3 | X-1004, X-1013 |
| `crates/busbar-kernel/src/config/tests/config_consolidation_tests.rs` | FINDING | `grep -n "path.*config_consolidation_tests.rs" crates/busbar-kernel/src/config/overlay.rs` -> 1 hit; 223 lines; 6 `#[test]`, 19 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/config/tests/entry_patch_tests.rs` | FINDING | `grep -n "path.*entry_patch_tests.rs" crates/busbar-kernel/src/config/patch.rs` -> 1 hit; 111 lines; 8 `#[test]`, 10 `assert`; plane-noun scan (comment-stripped): 2 code / 2 incl. comments | X-1013 |
| `crates/busbar-kernel/src/config/tests/groups_tests.rs` | FINDING | `grep -n "path.*groups_tests.rs" crates/busbar-kernel/src/config/groups.rs` -> 1 hit; 266 lines; 7 `#[test]`, 37 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/config/tests/groups.rs` | CLEAN | `grep -n "path.*groups.rs" crates/busbar-kernel/src/config/groups.rs` -> 1 hit; 136 lines; 5 `#[test]`, 12 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/config/tests/hooks.rs` | CLEAN | `grep -n "path.*hooks.rs" crates/busbar-kernel/src/config/hooks.rs` -> 1 hit; 39 lines; 3 `#[test]`, 4 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/config/tests/migrate_tests.rs` | FINDING | `grep -n "path.*migrate_tests.rs" crates/busbar-kernel/src/config/migrate.rs` -> 1 hit; 2645 lines; 47 `#[test]`, 265 `assert`; plane-noun scan (comment-stripped): 2 code / 4 incl. comments | X-1013 |
| `crates/busbar-kernel/src/config/tests/named_map_merge_tests.rs` | CLEAN | `grep -n "path.*named_map_merge_tests.rs" crates/busbar-kernel/src/config/mod.rs` -> 1 hit; 211 lines; 7 `#[test]`, 14 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/config/tests/named_map_tests.rs` | CLEAN | `grep -n "path.*named_map_tests.rs" crates/busbar-kernel/src/config/named_map.rs` -> 1 hit; 133 lines; 4 `#[test]`, 15 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/config/tests/overlay_read_only_tests.rs` | CLEAN | `grep -n "path.*overlay_read_only_tests.rs" crates/busbar-kernel/src/config/overlay.rs` -> 1 hit; 205 lines; 6 `#[test]`, 13 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/config/tests/overlay_tests.rs` | FINDING | `grep -n "path.*overlay_tests.rs" crates/busbar-kernel/src/config/overlay.rs` -> 1 hit; 932 lines; 31 `#[test]`, 97 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/config/tests/patch_tests.rs` | FINDING | `grep -n "path.*patch_tests.rs" crates/busbar-kernel/src/config/patch.rs` -> 1 hit; 140 lines; 4 `#[test]`, 6 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/config/tests/resolver_tests.rs` | FINDING | `grep -n "path.*resolver_tests.rs" crates/busbar-kernel/src/config/secret.rs` -> 1 hit; 76 lines; 3 `#[test]`, 7 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/config/tests/secret_tests.rs` | FINDING | `grep -n "path.*secret_tests.rs" crates/busbar-kernel/src/config/secret.rs` -> 1 hit; 160 lines; 8 `#[test]`, 21 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/config/tests/settings_resolution_tests.rs` | FINDING | `grep -n "path.*settings_resolution_tests.rs" crates/busbar-kernel/src/config/secret.rs` -> 1 hit; 129 lines; 5 `#[test]`, 11 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/config/tests/tests.rs` | FINDING | `grep -n "path.*tests.rs" crates/busbar-kernel/src/config/mod.rs` -> 1 hit; 4049 lines; 121 `#[test]`, 512 `assert`; plane-noun scan (comment-stripped): 4 code / 8 incl. comments; deleted-crate names: 3 | X-1004, X-1013 |
| `crates/busbar-kernel/src/config/tests/txn_fence.rs` | CLEAN | `grep -n "path.*txn_fence.rs" crates/busbar-kernel/src/config/transaction.rs` -> 1 hit; 53 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/config/tests/txn_loom.rs` | CLEAN | `grep -n "path.*txn_loom.rs" crates/busbar-kernel/src/config/transaction.rs` -> 1 hit; 156 lines; 2 `#[test]`, 5 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/config/tests/version_gate_tests.rs` | FINDING | `grep -n "path.*version_gate_tests.rs" crates/busbar-kernel/src/config/overlay.rs` -> 1 hit; 51 lines; 1 `#[test]`, 4 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/config/transaction.rs` | FINDING | `grep -nE "^\s*(pub )?mod transaction;" crates/busbar-kernel/src/config/mod.rs` -> 1 hit; 368 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 3 | X-1004 |
| `crates/busbar-kernel/src/core_routes.rs` | CLEAN | `grep -nE "^\s*(pub )?mod core_routes;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 166 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/detached.rs` | CLEAN | `grep -nE "^\s*(pub )?mod detached;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 141 lines; plane-noun scan (comment-stripped): 0 code / 2 incl. comments | - |
| `crates/busbar-kernel/src/diagnostics/mod.rs` | FINDING | `grep -nE "^\s*(pub )?mod diagnostics;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 61 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/diagnostics/tests.rs` | FINDING | `grep -nE "^\s*(pub )?mod tests;" crates/busbar-kernel/src/diagnostics/mod.rs` -> 1 hit; 96 lines; 1 `#[test]`, 2 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 5 | X-1004 |
| `crates/busbar-kernel/src/drain.rs` | FINDING | `grep -nE "^\s*(pub )?mod drain;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 120 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 15 | X-1004 |
| `crates/busbar-kernel/src/egress_auth/bearer_token.rs` | FINDING | `grep -nE "^\s*(pub )?mod bearer_token;" crates/busbar-kernel/src/egress_auth/mod.rs` -> 1 hit; 257 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1012, X-1004 |
| `crates/busbar-kernel/src/egress_auth/gate.rs` | FINDING | `grep -nE "^\s*(pub )?mod gate;" crates/busbar-kernel/src/egress_auth/mod.rs` -> 1 hit; 198 lines; plane-noun scan (comment-stripped): 0 code / 2 incl. comments; deleted-crate names: 2 | X-1004 |
| `crates/busbar-kernel/src/egress_auth/mod.rs` | FINDING | `grep -nE "^\s*(pub )?mod egress_auth;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 362 lines; plane-noun scan (comment-stripped): 0 code / 9 incl. comments; deleted-crate names: 5 | X-1012, X-1004 |
| `crates/busbar-kernel/src/egress_auth/oauth_client_credentials.rs` | FINDING | `grep -nE "^\s*(pub )?mod oauth_client_credentials;" crates/busbar-kernel/src/egress_auth/mod.rs` -> 1 hit; 189 lines; plane-noun scan (comment-stripped): 0 code / 1 incl. comments | X-1012 |
| `crates/busbar-kernel/src/egress_auth/tests/bearer_token_tests.rs` | FINDING | `grep -n "path.*bearer_token_tests.rs" crates/busbar-kernel/src/egress_auth/bearer_token.rs` -> 1 hit; 199 lines; 10 `#[test]`, 27 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/egress_auth/tests/gate_tests.rs` | FINDING | `grep -n "path.*gate_tests.rs" crates/busbar-kernel/src/egress_auth/gate.rs` -> 1 hit; 372 lines; 8 `#[test]`, 20 `assert`; plane-noun scan (comment-stripped): 0 code / 4 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/egress_auth/tests/helper_tests.rs` | FINDING | `grep -n "path.*helper_tests.rs" crates/busbar-kernel/src/egress_auth/mod.rs` -> 1 hit; 76 lines; 2 `#[test]`, 3 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 2 | X-1004 |
| `crates/busbar-kernel/src/egress_auth/tests/jwt_bearer_tests.rs` | FINDING | `grep -n "path.*jwt_bearer_tests.rs" crates/busbar-kernel/src/egress_auth/jwt_bearer.rs` -> 1 hit; 391 lines; 14 `#[test]`, 45 `assert`; plane-noun scan (comment-stripped): 0 code / 1 incl. comments; deleted-crate names: 2 | X-1004 |
| `crates/busbar-kernel/src/egress_auth/tests/license_tests.rs` | CLEAN | `grep -n "path.*license_tests.rs" crates/busbar-kernel/src/egress_auth/mod.rs` -> 1 hit; 39 lines; 1 `#[test]`, 1 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/egress_auth/tests/oauth_client_credentials_tests.rs` | FINDING | `grep -n "path.*oauth_client_credentials_tests.rs" crates/busbar-kernel/src/egress_auth/oauth_client_credentials.rs` -> 1 hit; 164 lines; 8 `#[test]`, 22 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 2 | X-1004 |
| `crates/busbar-kernel/src/egress_auth/tests/prebuilt_auth_tests.rs` | FINDING | `grep -n "path.*prebuilt_auth_tests.rs" crates/busbar-kernel/src/egress_auth/mod.rs` -> 1 hit; 91 lines; 2 `#[test]`, 6 `assert`; plane-noun scan (comment-stripped): 8 code / 12 incl. comments | X-1013 |
| `crates/busbar-kernel/src/egress/duplex_ws.rs` | CLEAN | `grep -nE "^\s*(pub )?mod duplex_ws;" crates/busbar-kernel/src/egress/mod.rs` -> 1 hit; 313 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/egress/engine/client.rs` | CLEAN | `grep -nE "^\s*(pub )?mod client;" crates/busbar-kernel/src/egress/engine/mod.rs` -> 1 hit; 408 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/egress/engine/deadline.rs` | CLEAN | `grep -nE "^\s*(pub )?mod deadline;" crates/busbar-kernel/src/egress/engine/mod.rs` -> 1 hit; 61 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/egress/engine/mod.rs` | FINDING | `grep -nE "^\s*(pub )?mod engine;" crates/busbar-kernel/src/egress/mod.rs` -> 1 hit; 1211 lines; plane-noun scan (comment-stripped): 0 code / 1 incl. comments; deleted-crate names: 2 | X-1004 |
| `crates/busbar-kernel/src/egress/engine/observe.rs` | CLEAN | `grep -nE "^\s*(pub )?mod observe;" crates/busbar-kernel/src/egress/engine/mod.rs` -> 1 hit; 195 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/egress/engine/pool.rs` | CLEAN | `grep -nE "^\s*(pub )?mod pool;" crates/busbar-kernel/src/egress/engine/mod.rs` -> 1 hit; 886 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/egress/engine/tests/engine_tests.rs` | FINDING | `grep -n "path.*engine_tests.rs" crates/busbar-kernel/src/egress/engine/mod.rs` -> 1 hit; 574 lines; 13 `#[test]`, 76 `assert`; plane-noun scan (comment-stripped): 6 code / 7 incl. comments | X-1013 |
| `crates/busbar-kernel/src/egress/engine/tests/observe_tests.rs` | CLEAN | `grep -n "path.*observe_tests.rs" crates/busbar-kernel/src/egress/engine/mod.rs` -> 1 hit; 314 lines; 4 `#[test]`, 15 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/egress/engine/tests/pool_h2_tests.rs` | CLEAN | `grep -n "path.*pool_h2_tests.rs" crates/busbar-kernel/src/egress/engine/mod.rs` -> 1 hit; 553 lines; 5 `#[test]`, 23 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/egress/engine/tests/pool_tests.rs` | FINDING | `grep -n "path.*pool_tests.rs" crates/busbar-kernel/src/egress/engine/mod.rs` -> 1 hit; 1510 lines; 21 `#[test]`, 72 `assert`; plane-noun scan (comment-stripped): 1 code / 1 incl. comments; deleted-crate names: 1 | X-1004, X-1013 |
| `crates/busbar-kernel/src/egress/engine/tests/tls_tests.rs` | CLEAN | `grep -n "path.*tls_tests.rs" crates/busbar-kernel/src/egress/engine/mod.rs` -> 1 hit; 410 lines; 6 `#[test]`, 21 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/egress/fixtures.rs` | FINDING | `grep -nE "^\s*(pub )?mod fixtures;" crates/busbar-kernel/src/egress/mod.rs` -> 1 hit; 521 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 2 | X-1004 |
| `crates/busbar-kernel/src/egress/mod.rs` | FINDING | `grep -nE "^\s*(pub )?mod egress;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 399 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 5 | X-1011, X-1004 |
| `crates/busbar-kernel/src/egress/seam.rs` | FINDING | `grep -nE "^\s*(pub )?mod seam;" crates/busbar-kernel/src/egress/mod.rs` -> 1 hit; 574 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 2 | X-1004 |
| `crates/busbar-kernel/src/egress/tests/duplex_ws_tests.rs` | CLEAN | `grep -n "path.*duplex_ws_tests.rs" crates/busbar-kernel/src/egress/duplex_ws.rs` -> 1 hit; 689 lines; 11 `#[test]`, 31 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/egress/tests/pinned_pool_tests.rs` | CLEAN | `grep -n "path.*pinned_pool_tests.rs" crates/busbar-kernel/src/egress/mod.rs` -> 1 hit; 197 lines; 6 `#[test]`, 9 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/endpoints.rs` | CLEAN | `grep -nE "^\s*(pub )?mod endpoints;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 294 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/engine_facade.rs` | FINDING | `grep -nE "^\s*(pub )?mod engine_facade;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 79 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 3 | X-1004 |
| `crates/busbar-kernel/src/export/file.rs` | CLEAN | `grep -nE "^\s*(pub )?mod file;" crates/busbar-kernel/src/export/mod.rs` -> 1 hit; 210 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/export/mod.rs` | CLEAN | `grep -nE "^\s*(pub )?mod export;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 169 lines; plane-noun scan (comment-stripped): 0 code / 1 incl. comments | - |
| `crates/busbar-kernel/src/export/prometheus.rs` | CLEAN | `grep -nE "^\s*(pub )?mod prometheus;" crates/busbar-kernel/src/export/mod.rs` -> 1 hit; 137 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/export/tests/file_tests.rs` | CLEAN | `grep -n "path.*file_tests.rs" crates/busbar-kernel/src/export/file.rs` -> 1 hit; 190 lines; 2 `#[test]`, 7 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/export/tests/projection_tests.rs` | FINDING | `grep -n "path.*projection_tests.rs" crates/busbar-kernel/src/export/projection.rs` -> 1 hit; 482 lines; 21 `#[test]`, 48 `assert`; plane-noun scan (comment-stripped): 4 code / 4 incl. comments; deleted-crate names: 1 | X-1004, X-1013 |
| `crates/busbar-kernel/src/export/tests/prometheus_tests.rs` | CLEAN | `grep -n "path.*prometheus_tests.rs" crates/busbar-kernel/src/export/prometheus.rs` -> 1 hit; 87 lines; 3 `#[test]`, 10 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/export/tests/webhook_tests.rs` | CLEAN | `grep -n "path.*webhook_tests.rs" crates/busbar-kernel/src/export/webhook.rs` -> 1 hit; 275 lines; 5 `#[test]`, 27 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/export/webhook.rs` | CLEAN | `grep -nE "^\s*(pub )?mod webhook;" crates/busbar-kernel/src/export/mod.rs` -> 1 hit; 213 lines; plane-noun scan (comment-stripped): 0 code / 1 incl. comments | - |
| `crates/busbar-kernel/src/failover/tests/failover_tests.rs` | FINDING | `grep -n "path.*failover_tests.rs" crates/busbar-kernel/src/failover/mod.rs` -> 1 hit; 828 lines; 15 `#[test]`, 47 `assert`; plane-noun scan (comment-stripped): 18 code / 18 incl. comments | X-1013 |
| `crates/busbar-kernel/src/governance/group_provision.rs` | CLEAN | `grep -nE "^\s*(pub )?mod group_provision;" crates/busbar-kernel/src/governance/mod.rs` -> 1 hit; 220 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/governance/mint_policy.rs` | FINDING | `grep -nE "^\s*(pub )?mod mint_policy;" crates/busbar-kernel/src/governance/mod.rs` -> 1 hit; 262 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | X-1001 |
| `crates/busbar-kernel/src/governance/revocation.rs` | CLEAN | `grep -nE "^\s*(pub )?mod revocation;" crates/busbar-kernel/src/governance/mod.rs` -> 1 hit; 214 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/governance/signing.rs` | FINDING | `grep -nE "^\s*(pub )?mod signing;" crates/busbar-kernel/src/governance/mod.rs` -> 1 hit; 397 lines; plane-noun scan (comment-stripped): 0 code / 6 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/governance/tests/budget_cell_tests.rs` | FINDING | `grep -n "path.*budget_cell_tests.rs" crates/busbar-kernel/src/governance/mod.rs` -> 1 hit; 54 lines; 1 `#[test]`, 6 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/governance/tests/limits_tests.rs` | CLEAN | `grep -n "path.*limits_tests.rs" crates/busbar-kernel/src/governance/mod.rs` -> 1 hit; 1098 lines; 24 `#[test]`, 52 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/governance/tests/mint_policy_tests.rs` | FINDING | `grep -n "path.*mint_policy_tests.rs" crates/busbar-kernel/src/governance/mint_policy.rs` -> 1 hit; 254 lines; 11 `#[test]`, 21 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/governance/tests/revocation_tests.rs` | FINDING | `grep -n "path.*revocation_tests.rs" crates/busbar-kernel/src/governance/revocation.rs` -> 1 hit; 265 lines; 3 `#[test]`, 11 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/governance/tests/signing_tests.rs` | FINDING | `grep -n "path.*signing_tests.rs" crates/busbar-kernel/src/governance/signing.rs` -> 1 hit; 292 lines; 12 `#[test]`, 28 `assert`; plane-noun scan (comment-stripped): 13 code / 15 incl. comments; deleted-crate names: 1 | X-1004, X-1013 |
| `crates/busbar-kernel/src/governance/tests/tests.rs` | CLEAN | `grep -n "path.*tests.rs" crates/busbar-kernel/src/governance/mod.rs` -> 1 hit; 5334 lines; 97 `#[test]`, 447 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/grammar.rs` | FINDING | `grep -nE "^\s*(pub )?mod grammar;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 125 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 2 | X-1004 |
| `crates/busbar-kernel/src/handlers/mod.rs` | FINDING | `grep -nE "^\s*(pub )?mod handlers;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 195 lines; plane-noun scan (comment-stripped): 0 code / 23 incl. comments; deleted-crate names: 10 | X-1004 |
| `crates/busbar-kernel/src/handlers/tests/chat_fixture.rs` | FINDING | `grep -n "path.*chat_fixture.rs" crates/busbar-kernel/src/handlers/mod.rs` -> 1 hit; 21 lines; plane-noun scan (comment-stripped): 1 code / 4 incl. comments | X-1013 |
| `crates/busbar-kernel/src/handlers/tests/contract_tests.rs` | CLEAN | `grep -n "path.*contract_tests.rs" crates/busbar-kernel/src/handlers/mod.rs` -> 1 hit; 67 lines; 2 `#[test]`, 4 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/handlers/tests/dispatch_tests.rs` | FINDING | `grep -n "path.*dispatch_tests.rs" crates/busbar-kernel/src/handlers/mod.rs` -> 1 hit; 138 lines; 3 `#[test]`, 13 `assert`; plane-noun scan (comment-stripped): 2 code / 4 incl. comments | X-1013 |
| `crates/busbar-kernel/src/handlers/tests/registry_tests.rs` | FINDING | `grep -n "path.*registry_tests.rs" crates/busbar-kernel/src/handlers/mod.rs` -> 1 hit; 34 lines; 2 `#[test]`, 4 `assert`; plane-noun scan (comment-stripped): 7 code / 7 incl. comments | X-1013 |
| `crates/busbar-kernel/src/hooks/gate.rs` | CLEAN | `grep -nE "^\s*(pub )?mod gate;" crates/busbar-kernel/src/hooks/mod.rs` -> 1 hit; 423 lines; plane-noun scan (comment-stripped): 0 code / 5 incl. comments | - |
| `crates/busbar-kernel/src/hooks/mod.rs` | FINDING | `grep -nE "^\s*(pub )?mod hooks;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 1822 lines; plane-noun scan (comment-stripped): 0 code / 5 incl. comments; deleted-crate names: 3 | X-1004 |
| `crates/busbar-kernel/src/hooks/plugin.rs` | CLEAN | `grep -nE "^\s*(pub )?mod plugin;" crates/busbar-kernel/src/hooks/mod.rs` -> 1 hit; 93 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/hooks/scrape.rs` | CLEAN | `grep -nE "^\s*(pub )?mod scrape;" crates/busbar-kernel/src/hooks/mod.rs` -> 1 hit; 397 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/hooks/tests/gate_tests.rs` | FINDING | `grep -n "path.*gate_tests.rs" crates/busbar-kernel/src/hooks/gate.rs` -> 1 hit; 790 lines; 14 `#[test]`, 36 `assert`; plane-noun scan (comment-stripped): 16 code / 18 incl. comments | X-1013 |
| `crates/busbar-kernel/src/hooks/tests/scrape_tests.rs` | CLEAN | `grep -n "path.*scrape_tests.rs" crates/busbar-kernel/src/hooks/scrape.rs` -> 1 hit; 393 lines; 13 `#[test]`, 36 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/hooks/tests/tests.rs` | CLEAN | `grep -n "path.*tests.rs" crates/busbar-kernel/src/hooks/mod.rs` -> 1 hit; 2689 lines; 57 `#[test]`, 155 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/hooks/tests/wire_tests.rs` | FINDING | `grep -n "path.*wire_tests.rs" crates/busbar-kernel/src/hooks/wire.rs` -> 1 hit; 526 lines; 19 `#[test]`, 80 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/ingress/arrival_host.rs` | FINDING | `grep -nE "^\s*(pub )?mod arrival_host;" crates/busbar-kernel/src/ingress/mod.rs` -> 1 hit; 93 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/ingress/byte_duplex.rs` | CLEAN | `grep -nE "^\s*(pub )?mod byte_duplex;" crates/busbar-kernel/src/ingress/mod.rs` -> 1 hit; 611 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/ingress/dispatch.rs` | FINDING | `grep -nE "^\s*(pub )?mod dispatch;" crates/busbar-kernel/src/ingress/mod.rs` -> 1 hit; 147 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/ingress/jsonrpc.rs` | CLEAN | `grep -nE "^\s*(pub )?mod jsonrpc;" crates/busbar-kernel/src/ingress/mod.rs` -> 1 hit; 511 lines; plane-noun scan (comment-stripped): 0 code / 25 incl. comments | - |
| `crates/busbar-kernel/src/ingress/native.rs` | CLEAN | `grep -nE "^\s*(pub )?mod native;" crates/busbar-kernel/src/ingress/mod.rs` -> 1 hit; 75 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/ingress/path_ingress.rs` | DELETABLE | `grep -nE "^\s*(pub )?mod path_ingress;" crates/busbar-kernel/src/ingress/mod.rs` -> 1 hit; 28 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 2 | X-1010, X-1004 |
| `crates/busbar-kernel/src/ingress/tests/byte_duplex_tests.rs` | FINDING | `grep -n "path.*byte_duplex_tests.rs" crates/busbar-kernel/src/ingress/byte_duplex.rs` -> 1 hit; 562 lines; 13 `#[test]`, 22 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/ingress/tests/jsonrpc_tests.rs` | CLEAN | `grep -n "path.*jsonrpc_tests.rs" crates/busbar-kernel/src/ingress/jsonrpc.rs` -> 1 hit; 342 lines; 17 `#[test]`, 34 `assert`; plane-noun scan (comment-stripped): 0 code / 4 incl. comments | - |
| `crates/busbar-kernel/src/ir/egress_prep.rs` | FINDING | `grep -nE "^\s*(pub )?mod egress_prep;" crates/busbar-kernel/src/ir/mod.rs` -> 1 hit; 14 lines; plane-noun scan (comment-stripped): 0 code / 1 incl. comments; deleted-crate names: 2 | X-1004 |
| `crates/busbar-kernel/src/ir/facts.rs` | FINDING | `grep -nE "^\s*(pub )?mod facts;" crates/busbar-kernel/src/ir/mod.rs` -> 1 hit; 17 lines; plane-noun scan (comment-stripped): 0 code / 2 incl. comments; deleted-crate names: 2 | X-1004 |
| `crates/busbar-kernel/src/ir/handle.rs` | FINDING | `grep -nE "^\s*(pub )?mod handle;" crates/busbar-kernel/src/ir/mod.rs` -> 1 hit; 15 lines; plane-noun scan (comment-stripped): 0 code / 1 incl. comments; deleted-crate names: 2 | X-1004 |
| `crates/busbar-kernel/src/ir/invoke.rs` | FINDING | `grep -nE "^\s*(pub )?mod invoke;" crates/busbar-kernel/src/ir/mod.rs` -> 1 hit; 50 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1005, X-1004 |
| `crates/busbar-kernel/src/ir/mod.rs` | FINDING | `grep -nE "^\s*(pub )?mod ir;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 51 lines; plane-noun scan (comment-stripped): 0 code / 6 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/ir/neutral_handles.rs` | FINDING | `grep -nE "^\s*(pub )?mod neutral_handles;" crates/busbar-kernel/src/ir/mod.rs` -> 1 hit; 12 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/ir/subscribe.rs` | FINDING | `grep -nE "^\s*(pub )?mod subscribe;" crates/busbar-kernel/src/ir/mod.rs` -> 1 hit; 47 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1005, X-1004 |
| `crates/busbar-kernel/src/ir/tests/subscribe_tests.rs` | FINDING | `grep -n "path.*subscribe_tests.rs" crates/busbar-kernel/src/ir/subscribe.rs` -> 1 hit; 33 lines; 1 `#[test]`, 7 `assert`; plane-noun scan (comment-stripped): 5 code / 5 incl. comments; deleted-crate names: 1 | X-1004, X-1013 |
| `crates/busbar-kernel/src/limits/admission.rs` | CLEAN | `grep -nE "^\s*(pub )?mod admission;" crates/busbar-kernel/src/limits/mod.rs` -> 1 hit; 194 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments | - |
| `crates/busbar-kernel/src/limits/mod.rs` | FINDING | `grep -nE "^\s*(pub )?mod limits;" crates/busbar-kernel/src/lib.rs` -> 1 hit; 152 lines; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1004 |
| `crates/busbar-kernel/src/limits/tests/admission_tests.rs` | FINDING | `grep -n "path.*admission_tests.rs" crates/busbar-kernel/src/limits/admission.rs` -> 1 hit; 170 lines; 6 `#[test]`, 16 `assert`; plane-noun scan (comment-stripped): 0 code / 0 incl. comments; deleted-crate names: 1 | X-1004 |

## ROWS RAISED

### X-1000 · `auth.policy.default_ttl` is declared, documented, schema'd and validated — and nothing reads it
CLASS:     config
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "default_ttl" -- 'crates/busbar-kernel/src/**/*.rs' 'crates/busbar-core-admin/src/**/*.rs' \
    | grep -v "_tests.rs\|/tests/\|session/mod.rs"
crates/busbar-kernel/src/config/auth.rs:236:    pub default_ttl: Option<String>,
crates/busbar-kernel/src/config/auth.rs:238:    /// admin API's own default applies). When both are set, `default_ttl` must be <= `max_ttl`
crates/busbar-kernel/src/config_validate/mod.rs:885:            .default_ttl
crates/busbar-kernel/src/config_validate/mod.rs:887:  .and_then(|t| parse_policy_ttl("auth.policy.default_ttl", t, &mut errors));
crates/busbar-kernel/src/config_validate/mod.rs:895:  "auth.policy.default_ttl ('{}', {d}s) exceeds auth.policy.max_ttl ('{}', {m}s); \
crates/busbar-kernel/src/config_validate/mod.rs:897:                    policy.default_ttl.as_deref().unwrap_or(""),
```
Four hits: one declaration, one doc line, two validation sites. **Zero consumers.**
`MintPolicy` (`governance/mint_policy.rs:65-82`) has no `default_ttl` field and
`MintPolicy::from_auth` (`:106-140`) never copies it. The only place a "request named no
lifetime" default is produced is the hard-coded constant:
```
$ sed -n '741p' crates/busbar-core-admin/src/keys.rs
        (None, None) => (now.saturating_add(DEFAULT_KEY_TTL_SECS), false),
```
`DEFAULT_KEY_TTL_SECS = 90 * 86_400` (`governance/mint_policy.rs:50`).

POSITIVE CONTROL — the sibling key in the same struct, same grep shape, IS consumed:
```
$ git grep -n "max_ttl" -- 'crates/busbar-kernel/src/governance/mint_policy.rs'
crates/busbar-kernel/src/governance/mint_policy.rs:115:            block_max_ttl_secs: policy
crates/busbar-kernel/src/governance/mint_policy.rs:116:                .max_ttl
```
So the zero for `default_ttl` is a measurement, not a dead grep.

EFFECT: an operator who writes `auth.policy.default_ttl: 24h` gets a CLEAN boot (the key parses,
is range-checked against `max_ttl`, and appears in `config-schema.snapshot.json:195`) and then
90-day keys. `docs/design/1.6.0-config-surface.md:281` documents it as "the TTL an omitted expiry
takes" and `:511` marks it IMPLEMENTED-NOT-DOCUMENTED — the ledger believes it is wired.

ACTION:    add `default_ttl_secs: Option<u64>` to `MintPolicy`, populate it in
`MintPolicy::from_auth` from `policy.default_ttl` through `parse_duration_secs`, and read it at
`crates/busbar-core-admin/src/keys.rs:741` in place of the bare `DEFAULT_KEY_TTL_SECS`
(`app.mint_policy.default_ttl_secs.unwrap_or(DEFAULT_KEY_TTL_SECS)`). If instead the key is not
wanted, DELETE it from `AuthPolicyCfg`, from `config_validate/mod.rs:885-899`, from the schema
snapshot and from the config-surface doc — a validated key nothing reads is worse than no key.

### X-1001 · the mint ceiling binds ONE of the two mint paths: `POST /auth/token` is not checked at all
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "check_mint(" -- '*.rs' | grep -v "_tests.rs\|/tests/"
crates/busbar-core-admin/src/keys.rs:764:    let exp = match app.mint_policy.check_mint(&mint_req) {
crates/busbar-kernel/src/governance/mint_policy.rs:202:    pub fn check_mint(&self, req: &MintRequest<'_>) -> Result<u64, String> {
```
ONE caller: the admin `POST /keys` handler. The self-serve mint reads only `self_mint`:
```
$ sed -n '71p;83p' crates/busbar-kernel/src/auth/exchange.rs
        match resolve_exchange(&verdict, &app.role_bindings, app.mint_policy.self_mint) {
    let ttl = Duration::from_secs(app.self_key_ttl_secs);
```
`self_key_ttl_secs` is built independently of the policy (`appbuild.rs:1906-1914`: it reads
`auth.key_ttl` and falls back to `DEFAULT_KEY_TTL_SECS`; `mint_policy` is constructed two lines
later at `:1918` and never consulted here). `issue_key` (`auth/self_keys.rs:392-404`) passes the
`ttl` straight to `SelfServeKeys::issue`, which does `exp = now.saturating_add(ttl.as_secs())`
(`:125-126`) — no clamp on the way.

The DECLARATION says otherwise, in three places:
* `governance/mint_policy.rs:16-17` — "the block-level cap that bounds **how long any minted
  token may live**";
* `governance/mint_policy.rs:74-75` — "Deployment-wide TTL ceiling (`auth.policy.max_ttl`). **A
  hard cap**";
* `config/auth.rs:239-240` — "The MAX TTL **any minted token** may carry".

EFFECT: `auth.policy.max_ttl: 1h` + `auth.policy.mint_ceilings.<role>.{max_ttl,allowed_pools,
binding_modes}` bound the admin surface and are silently absent from `POST /auth/token` and from
the browser login flow (`auth/token.rs:628` takes the same `self_mint`-only branch). The
self-serve key is a real persisted binding with pools, so the `allowed_pools` ceiling is bypassed
too — `resolve_exchange` derives pools from `role_bindings.allowed_pools` and never looks at
`mint_ceilings`. This is the "compromised delegated admin" threat (`config/auth.rs:198`, review
H2/H3) with a second, unguarded door.

ACTION:    thread the policy into the self-serve path. In `auth/exchange.rs` (and the twin site in
`auth/token.rs`) build a `MintRequest { roles: &principal.roles, requested_pools: pools.as_deref(),
requested_ttl_secs: app.self_key_ttl_secs, explicit_ttl: false, requested_mode:
Some(SELF_KEY_BINDING_MODE_*) }` and take the TTL from `app.mint_policy.check_mint(&req)?` instead
of from `app.self_key_ttl_secs` directly — `explicit_ttl: false` gives the documented CLAMP (not a
refusal) for a configured default that outruns the ceiling, which is the correct arm for a path
where the caller never named a lifetime.

### X-1002 · core names a plane type and a plane wire key in production code
CLASS:     abi
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "Mcp\|\.mcp\b" -- 'crates/busbar-kernel/src/config/mod.rs'
52:use crate::plane::config::McpEndpointSection; // plane-purity: frozen-wire ...
1157: // Type-erased through the neutral `McpEndpointSection` seam: ...
1166:    pub mcp: McpEndpointSection, // plane-purity: frozen-wire the mcp: top-level wire key ...
2626: // plane-purity: frozen-wire deploy.mcp is the frozen mcp: wire field on DeployCfg
2627:    let endpoint_block = deploy.mcp.0.as_ref();
```
These are the ONLY plane-named lines in the 83 production files of this slice. The
comment-stripped scan over all 83 returns exactly these 3 code lines; the same scan over
`src/config/tests/tests.rs` returns 4 (positive control), so the 80 zeros are measurements.

Every one carries an in-source `plane-purity: frozen-wire` waiver, so the gate is green by
declaration, not by absence. `BUSBAR-1.6.0.md` Part 0 "What done means" clause 2 is unconditional:
every `Family::Neutral` crate names **ZERO** plane vocabulary in source, **ceiling 0 and ARMED,
with no ratchet row able to raise it**. `busbar-kernel` is `Family::Neutral`
(`xtask/src/gates/kind_isolation.rs:285-289`). A frozen-wire waiver is a ratchet row by another
name.

ACTION:    PARK for the owner — this is a frozen 1.5.3 wire key, so removing the *field* is a
config-surface change the oracle governs. The type name is not: rename `McpEndpointSection` to a
neutral `PlaneEndpointSection` (it is already a `dyn PlaneEndpointCfg` carrier per the comment at
`:1157-1160`, so the name is the only plane-bearing part), and keep the `mcp:` wire STRING behind
the `prepass` lift it already uses so `DeployCfg` carries an anonymous carrier rather than a
plane-named field. The owner must rule on whether the frozen `mcp:` key itself is in scope.

### X-1003 · plane identity is laundered through a positional index the neutrality scanner cannot see
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:
```
$ grep -n "NAMED_MAP_SECTIONS" crates/busbar-kernel/src/plane/config.rs | tail -1
757:pub const NAMED_MAP_SECTIONS: [&str; 4] = ["identity-providers", "export", "tools", "agents"];

$ git grep -c "NAMED_MAP_SECTIONS\[" -- 'crates/busbar-kernel/src/config/mod.rs'
4
$ sed -n '2229,2230p;2636p;2672p' crates/busbar-kernel/src/config/mod.rs
        let tools_section = busbar_kernel::plane::config::NAMED_MAP_SECTIONS[2];
        let agents_section = busbar_kernel::plane::config::NAMED_MAP_SECTIONS[3];
                    busbar_kernel::plane::config::NAMED_MAP_SECTIONS[2],
            busbar_kernel::plane::config::NAMED_MAP_SECTIONS[2],
```
`[2]` is `"tools"` (the MCP plane) and `[3]` is `"agents"` (the A2A plane). The surrounding
comment states the coupling in words — `config/mod.rs:2632-2633`: *"The endpoint's owning plane is
looked up by its CONFIG SECTION (the `tools:` plane owns the `mcp:` door), so no plane key is
named here."* Core therefore still hard-codes *which plane owns which door*; only the spelling
moved.

THE INSTRUMENT CANNOT PRODUCE A NO. `xtask/src/gates/plane_purity/scanner.rs` is a literal scan
over six categories (`PATH-INCLUDE`, `SYMBOL`, `TYPE`, `KEY`, `DIALECT`, `BACKWARDS`,
`scanner.rs:32-40`) — every one of them matches a *token*. There is no rule that reads an index
into a plane-section array, so no edit to `config/mod.rs` short of re-introducing the literal
`"tools"` can make this red. `NAMED_MAP_SECTIONS[2]` appears **16 times across 6 files** in
`busbar-kernel` (`appbuild.rs`, `config_validate/mod.rs`, `plane/config.rs`, `config/mod.rs`,
`tests/plane_integration.rs`), all invisible to the gate.

Second-order hazard, independent of the gate: `NAMED_MAP_SECTIONS` is a `[&str; 4]` and the
indices are unnamed. Reordering the array — a one-line edit with no compile error and no test that
pins the ORDER — silently re-points the `mcp:` endpoint to the `agents:` plane.

ACTION:    replace the positional indices with named constants beside the array
(`pub const SECTION_TOOLS: &str = NAMED_MAP_SECTIONS[2];` is not enough — it re-introduces the
plane word). The honest fix is to stop core asking "which section owns the endpoint door" at all:
give `PlaneDecl` an `owns_endpoint_block: bool` (or have `lower_endpoint`'s presence BE the
answer) and have `config/mod.rs:2636` iterate the registered decls for the one that declares it,
instead of indexing. Then add a scanner rule for `NAMED_MAP_SECTIONS[<int>]` so the laundering
form is itself red.

### X-1004 · 185 live references to five DELETED crates, across 73 of this slice's 154 files
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ for c in busbar-core busbar-substrate busbar-caps busbar-grammar busbar-admin; do
    [ -d "crates/$c" ] && echo "EXISTS $c" || echo "GONE   $c"; done
GONE   busbar-core
GONE   busbar-substrate
GONE   busbar-caps
GONE   busbar-grammar
GONE   busbar-admin
$ ls -d crates/busbar-kernel                 # positive control: a live crate resolves
crates/busbar-kernel
```
A comment-preserving scan over the 154 slice files for `busbar[-_]core`, `busbar[-_]substrate`,
`busbar[-_]caps`, `busbar[-_]grammar`, `busbar[-_]admin`, `busbar-unit-` — with the LIVE spellings
`busbar-core-{admin,connsec,oauth2}` and `busbar-substrate-values` subtracted first — returns
**185 hits in 73 files**. Worst offenders:
```
15  crates/busbar-kernel/src/drain.rs
13  crates/busbar-kernel/src/admin/seam.rs
13  crates/busbar-kernel/src/config/limits.rs
10  crates/busbar-kernel/src/handlers/mod.rs
 9  crates/busbar-kernel/src/admin_witness.rs
 6  crates/busbar-kernel/src/admin/mod.rs
```
Three sub-classes, in rising severity:

1. **A stale crate NAME in prose** — `src/governance/tests/budget_cell_tests.rs:4` opens
   `//! Tests for crates/busbar-core/src/governance/mod.rs`. Harmless alone, 130-odd times over.
2. **A stale ARCHITECTURAL CLAIM.** `src/drain.rs:14` — *"Each step's implementation still
   physically lives in `busbar-core` today"* — and `:16-19` names the relocation target as
   `busbar-unit-<step>` crates. `qa/construction.toml:841` records that the twelve `busbar-unit-*`
   crates became eight `busbar-kernel-<name>` crates at W2.c. The module's whole stated purpose
   describes a migration that already happened, to a destination that no longer exists.
3. **A stale SYMBOL PATH, which is a falsifiable claim.** `src/admin/seam.rs:5` names
   `busbar_admin::v1::json::JsonV1`; `src/admin/v1/mod.rs:7` names `busbar_admin::v1`;
   `src/config/transaction.rs:350` names `busbar_admin::tests::txn_tests`. There is no
   `busbar_admin` crate — the real one is `busbar-core-admin`, a workspace member since the
   `busbar-core-<x>` split (`Cargo.toml` members list). These read as import paths and are not.

`kind-isolation:legacy-drain` (`xtask/src/gates/kind_isolation.rs:2148-2177`) measures crate
EXISTENCE against `[[transitional]]` rows, so it is green — correctly, since the crates ARE gone.
Nothing measures the 185 references they left behind.

ACTION:    a mechanical sweep, three substitutions in priority order —
`busbar_admin::` -> `busbar_core_admin::` / `busbar-admin` -> `busbar-core-admin` (a false symbol
path, fix first); `busbar-substrate` -> `busbar-substrate-values` where the item survived and
delete the "RELOCATED DOWN to busbar-substrate" sentence where it did not (most of `src/ir/*`,
`src/billing.rs`, `src/catalogue.rs`, `src/diagnostics/mod.rs` now re-export from the same crate or
from `busbar-substrate-values`); `busbar-core` -> `busbar-kernel`, and re-read `src/drain.rs`'s
header end to end — its `busbar-unit-<step>` destination is dead and its "still lives in
busbar-core" premise is false, so the module needs a rewritten rationale, not a rename. The
full 73-file list is the `X-1004` column of the table above.

### X-1005 · two module headers link to `crate::ir::variant`, a module that does not exist
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ git grep -n "ir::variant" -- 'crates/busbar-kernel/**/*.rs'
crates/busbar-kernel/src/ir/invoke.rs:4://! THE INVOKE IR — the `Operation::INVOKE` subclass of the parent [`crate::ir::variant::IrReq`]
crates/busbar-kernel/src/ir/invoke.rs:5://! / [`crate::ir::variant::IrResp`] enums.
crates/busbar-kernel/src/ir/subscribe.rs:5://! [`crate::ir::variant::IrReq`] / [`crate::ir::variant::IrResp`] enums.
$ grep -nE "^\s*pub mod" crates/busbar-kernel/src/ir/mod.rs
pub mod egress_prep;
pub mod facts;
pub mod handle;
pub mod invoke;
pub mod neutral_handles;
pub mod subscribe;
```
No `variant`. `ir/mod.rs:40-48` records why: *"`IrReq`/`IrResp` have dissolved"* at the G6 A4b
cutover and the concrete IR moved to `busbar-llm`. Both files are rustdoc intra-doc links in
`[...]` form, so they are unresolved-link warnings — the `doc-links` discipline
(`BUSBAR-1.6.0.md`, rustdoc `-D broken_intra_doc_links`) would red on them.

ACTION:    drop the two `[...]` links and restate the sentence against what survives — the
subclass parent is now `busbar_substrate_values::ir::handle::IrHandle`, which is what
`ir/handle.rs` re-exports. Same edit in both files.

### X-1006 · `benches/pool_upstream_creds.rs` measures a copy of a function that has left this crate, and asserts nothing
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  the bench says so itself, at `crates/busbar-kernel/benches/pool_upstream_creds.rs:11-13`:
```
//! This bench models the exact operation the accessor performs (the crate-internal `App`/`pub(crate)`
//! accessor is unreachable from a bench crate, so we reproduce its data shape faithfully: ...
```
Its whole measured surface is defined in the file: `enum Creds` (`:23`), `fn old_lookup` (`:41`),
`fn new_flag_copy` (`:48`). It never names a `busbar_kernel` item — there is no `use
busbar_kernel::…` in the file at all.
```
$ grep -c "assert" crates/busbar-kernel/benches/pool_upstream_creds.rs
0
```
No budget, no threshold, no `assert!` — **no input makes it red.** Contrast its sibling
`benches/plane_host_vtable_alloc.rs`, which carries `assert_eq!(allocations, 0, ...)` at `:137`
and a `BUSBAR_ALLOC_INJECT` knob that proves the red.

AND THE SUBJECT MOVED. The bench's named subject is `App::pool_upstream_creds`:
```
$ git grep -n "pool_upstream_creds" -- '*.rs' | grep -v benches
crates/busbar-kernel/src/state.rs:597:    /// Prefer [`App::pool_upstream_creds`] on any path that knows its pool: ...
crates/busbar-kernel/src/test_support/mod.rs:1488:    pub fn pool_upstream_creds(mut self, name: &str, uc: crate::auth::UpstreamCreds) -> Self {
crates/busbar-llm/src/engine/build_runtime.rs:295:    let any_pool_upstream_creds_override = pool_runtime
crates/busbar-llm/src/engine/exhaustion/mod.rs:301:            upstream_creds: EngineTables::new(rt).pool_upstream_creds(pool),
crates/busbar-llm/src/engine/mod.rs:203:#[path = "tests/pool_upstream_creds_tests.rs"]
```
There is no `App::pool_upstream_creds` in `busbar-kernel`. The accessor is
`EngineTables::pool_upstream_creds` and the `any_override` flag the bench is *about* is
`any_pool_upstream_creds_override`, both in **`busbar-llm`**. A bench in `busbar-kernel`
benchmarking a `busbar-llm` optimisation, via a hand-copied reimplementation, with no assertion:
the fast path could be deleted from `build_runtime.rs` and this instrument would print the same
three numbers.

`crates/busbar-kernel/src/state.rs:597`'s `[`App::pool_upstream_creds`]` is the same dangling
reference in doc-link form. **That file is outside this slice — reported, not acted on.**

ACTION:    move the bench to `crates/busbar-llm/benches/` beside the code it is about, drive the
REAL `EngineTables::pool_upstream_creds` (reachable there), and give it the budget its claim
implies — assert `new_flag_copy_no_override` p50 is under `old_lookup_no_override` p50, so a
regression that reinstates the per-request SipHash takes the process down non-zero. If the fast
path is no longer considered load-bearing, DELETE the bench and its `[[bench]]` row
(`crates/busbar-kernel/Cargo.toml`) — an unassertable micro-bench that measures its own copy is
not evidence of anything.

### X-1007 · `benches/plane_host_vtable_alloc.rs` documents a run command against a deleted crate
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '37p' crates/busbar-kernel/benches/plane_host_vtable_alloc.rs
//! cargo bench -p busbar-core --bench plane_host_vtable_alloc
$ ls -d crates/busbar-core
ls: crates/busbar-core: No such file or directory
```
`busbar-core` is DELETED (`BUSBAR-1.6.0.md` #19 — "the deletion is the release"), so the one
command the file gives an operator for reproducing the alloc budget fails with `error: package
ID specification 'busbar-core' did not match any packages`. The sibling
`benches/plane_host_vtable_perf.rs:45` carries the identical line — **that file is outside this
slice; reported, not acted on.**

The instrument itself is SOUND: `assert_zero_alloc_pod_batch` (`:119-146`) arms a counting
`#[global_allocator]` only around the batch, and `BUSBAR_ALLOC_INJECT` (`:124`, `:139-142`) is a
real red-prover. Its subject is bench-local by declared design (`:26-32`, "THE PENDING-RIDER
DEPENDENCY" — `PlaneHostVtable` has no production rider yet), which the file states rather than
hides, so it is not blind in the X-1006 sense.

ACTION:    `-p busbar-core` -> `-p busbar-kernel`, in both bench headers.

### X-1008 · `admin_witness`'s load-bearing rationale is the reason it must NOT live where it now lives
CLASS:     instrument-blind
CERTAINTY: ADJUDICATE
EVIDENCE:  `crates/busbar-kernel/src/admin_witness.rs:8-19` states the whole reason the ledger
exists as a separate home:
```
//! `busbar-core`'s own test binary links `busbar-core` TWICE: once as the crate-under-test
//! (`cfg(test)`) and once as an ordinary dependency of the extracted plane crates ... A
//! `static` witness set in `busbar-core` would therefore split in two ... `busbar-substrate` is a
//! plain dependency of all three crates, compiled ONCE with feature unification, so a witness
//! ledger here is the one both copies of `busbar-core` reach.
```
The file is `crates/busbar-kernel/src/admin_witness.rs`. `busbar-substrate` is deleted; the ledger
now lives in `busbar-kernel` — which IS the doubly-linked crate, by exactly the mechanism the
header describes: `crates/busbar-kernel/Cargo.toml` `[dev-dependencies]` carries
`busbar-a2a`/`busbar-mcp`/`busbar-llm`, each of which normal-depends on `busbar-kernel`. The
stated invariant ("compiled ONCE") no longer holds for the crate the static now sits in.

WHY THIS IS ADJUDICATE AND NOT VERIFIED: the ONE reader is in a third binary where the hazard does
not arise —
```
$ git grep -n "observed::snapshot()" -- '*.rs'
crates/busbar-core-admin/src/tests/tests.rs:12873:    let witnessed = busbar_kernel::admin::v1::contract::taxonomy::observed::snapshot();
```
In `busbar-core-admin`'s test binary `busbar-kernel` is a plain dependency compiled once, so the
over-claim half of `declared_error_set_is_exactly_what_the_handlers_emit`
(`busbar-core-admin/src/tests/tests.rs:12855`) currently reads a single, whole ledger. I did not
run the suite, so I am not claiming a live split — I am claiming the ARGUMENT that guarantees
there isn't one is false, and nothing re-derives it. The same is written a second time at
`crates/busbar-kernel/src/admin/v1/contract/taxonomy.rs:783-785` ("read from the process-wide
substrate ledger so BOTH copies of `busbar-core` ... contribute").

ACTION:    owner/architect ruling on where the witness belongs. If it stays in `busbar-kernel`,
replace both headers with the true guarantee — "the only reader is `busbar-core-admin`'s test
binary, in which `busbar-kernel` is compiled once" — and add a one-line assertion in that test
that the snapshot is non-empty before comparing, so a future split shows up as a hard failure
instead of a vacuous pass. If the doubly-linked case is ever meant to be read, the ledger must move
to a crate below `busbar-kernel` (`busbar-contract` or `busbar-substrate-values`).

### X-1009 · `audit_ring::list_filtered` ships in the release binary with zero callers
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  the file says it:
```
$ sed -n '341,347p' crates/busbar-kernel/src/audit_ring.rs
    /// NO PRODUCTION CALLER after the 1.6.0 seam read cutover: `GET /audit` reads the durable journal
    /// seam's [`crate::plane::auditlog::AUDIT_LOG`]. This in-process ring's `list_filtered`/`list`
    /// remain the direct-ring read the audit unit tests still assert on.
    #[allow(dead_code)]
    pub fn list_filtered(
```
The two neighbours in the same `impl` are correctly gated — `verify` is `#[cfg(test)]` (`:332`) and
`list` is `#[cfg(any(test, feature = "test-support"))]` (`:363`). `list_filtered` alone carries
`#[allow(dead_code)]` instead of a cfg, so it is the one item of the three compiled into a shipped
build, and its only caller (`list`) is compiled out there. "A capability that is never constructed
is a capability that does not ship" — this one ships and is never constructed.

ACTION:    change `#[allow(dead_code)]` to `#[cfg(any(test, feature = "test-support"))]`, matching
`list` directly below it. The `#[allow]` then becomes unnecessary and goes with it.

### X-1010 · `ingress/path_ingress.rs` is a relocation shim whose destination is the same crate
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  the module's entire body is three re-exports:
```
$ grep -nE "^(pub )?(pub\(crate\) )?use" crates/busbar-kernel/src/ingress/path_ingress.rs
15:pub use busbar_kernel::ingress::arrival::{install_path_ingress, PathIngress};
27:pub(crate) use busbar_kernel::ingress::arrival::path_ingress_for;
```
`busbar_kernel` is THIS crate (`crates/busbar-kernel/src/lib.rs:29: extern crate self as
busbar_kernel;`) and `ingress/arrival.rs` is its sibling file in the same directory:
```
$ ls crates/busbar-kernel/src/ingress/
arrival.rs  arrival_host.rs  byte_duplex.rs  dispatch.rs  duplex_ws.rs  jsonrpc.rs
mod.rs  native.rs  path_ingress.rs  protocol.rs  tests
```
Its stated reason (`:7-9`) — *"RELOCATED DOWN to `busbar-substrate` so the extracted dialect crate
names the registration-pair type ... This module re-exports those items at their historical
`busbar_kernel::ingress::path_ingress::…` paths"* — names a deleted crate and a move that came
back. Its one non-test consumer already reaches around it in the same expression:
```
$ sed -n '92p;104p' crates/busbar-kernel/src/ingress/dispatch.rs
    if let Some(path_ingress) = crate::ingress::path_ingress::path_ingress_for(proto) {
        return path_ingress(busbar_kernel::ingress::arrival::Arrival {
```
line 92 goes through the shim, line 104 goes straight to `arrival`.

ACTION:    DELETE `crates/busbar-kernel/src/ingress/path_ingress.rs`, its `pub mod path_ingress;`
at `crates/busbar-kernel/src/ingress/mod.rs:735`, and repoint the facade re-export one line below
(`mod.rs:738: pub use path_ingress::PathIngress;` -> `pub use arrival::PathIngress;`). Repoint
`ingress/dispatch.rs:92` to `crate::ingress::arrival::path_ingress_for` — which is what line 104
already does for the type beside it. There is no CODE consumer outside this crate:
`git grep -n "ingress::path_ingress" | grep -v crates/busbar-kernel/` returns two hits, both doc
comments in `crates/busbar-substrate-values/src/proto.rs:639,764`, which should be repointed to
`busbar_kernel::ingress::arrival` in the same edit.

### X-1011 · `egress/mod.rs` documents a test-only type as the production resolver
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:
```
$ sed -n '146,147p;159,160p' crates/busbar-kernel/src/egress/mod.rs
/// The client's own resolver, in production: one that refuses every name.
...
#[cfg(any(test, feature = "test-support"))]
pub struct RefuseSecondLookup;
```
The doc sentence and the cfg directly contradict each other: no shipped build compiles
`RefuseSecondLookup` at all. `build_pinned_client` (`:239`) carries the same doc claim at `:232`
("`dns_resolver` — the caller's resolver (production: [`RefuseSecondLookup`])") behind the same
cfg. The SHARED half is genuinely production —
```
$ git grep -n "refuse_second_lookup_message" -- '*.rs' | grep -v tests
crates/busbar-kernel/src/egress/engine/resolve.rs:136:  ResolveFuture::Ready(Some(Err(crate::egress::refuse_second_lookup_message(
crates/busbar-kernel/src/egress/mod.rs:168:pub fn refuse_second_lookup_message(name: &str) -> String {
```
— so the DNS-rebind refusal itself ships, through `engine::EgressResolver::Pinned`. Only the
attribution is wrong, and it is wrong in the one direction that matters: a reader auditing the
rebind guard is pointed at a type the release binary does not contain.

ACTION:    reword `:146` to "The reqwest REFERENCE stack's resolver (test/`test-support` only); the
production refusal is `engine::EgressResolver::Pinned`, which quotes the same
`refuse_second_lookup_message`." Same correction at `:232`.

### X-1012 · the outbound token TTL has no ceiling, where the inbound credential TTL does
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:  the INBOUND side caps a peer-suggested lifetime, and says why:
```
$ sed -n '27,29p;155,159p' crates/busbar-kernel/src/auth_cache.rs
/// Hard cap on any module-suggested `Identify` TTL, seconds — a module cannot pin a credential
/// valid for longer than this, no matter what it asks for.
const MAX_IDENTIFY_TTL_SECS: u64 = 3600;
...
                p.ttl_secs
                    .unwrap_or(DEFAULT_IDENTIFY_TTL_SECS)
                    .min(MAX_IDENTIFY_TTL_SECS),
```
The OUTBOUND mint has no equivalent:
```
$ git grep -nE "\.min\(|MAX_|clamp" -- 'crates/busbar-kernel/src/egress_auth/' | grep -v tests
crates/busbar-kernel/src/egress_auth/jwt_bearer.rs:227: // huge value must clamp to u64::MAX rather than wrap/panic.
crates/busbar-kernel/src/egress_auth/oauth_client_credentials.rs:170: // huge value must clamp to u64::MAX rather than wrap/panic.
```
Two hits, both comments on a `saturating_add` — an OVERFLOW guard, not a ceiling. The value being
guarded is acknowledged as hostile at `oauth_client_credentials.rs:169` and `jwt_bearer.rs:226`:
*"`expires_in` is attacker-influenced (comes off the token endpoint)"*. `deserialize_expires_in`
(`egress_auth/mod.rs:85-123`) deliberately widens what is accepted — integer, JSON float, or
numeric string — and `float_to_secs` (`:99-107`) refuses only negative and non-finite, so
`expires_in: 1e18` deserializes to `1e18 as u64` (Rust `as` saturates, no error). The refresh
scheduler then honours it verbatim:
```
$ sed -n '164,172p' crates/busbar-kernel/src/egress_auth/bearer_token.rs
fn next_refresh_secs(expires_at: u64, now: u64) -> u64 {
    let ttl = expires_at.saturating_sub(now);
    if ttl == 0 { MIN_SLEEP_SECS }
    else if ttl <= REFRESH_SKEW_SECS { (ttl / 2).max(1) }
    else { (ttl - REFRESH_SKEW_SECS).max(MIN_SLEEP_SECS) }
}
```
`next_refresh_secs` has a FLOOR (`MIN_SLEEP_SECS`) and no CEILING, so a single hostile or
misconfigured token-endpoint response pins the outbound bearer for the life of the process: the
re-mint loop sleeps effectively forever, and a credential the upstream later rotates or revokes is
never re-fetched. The broken pair is exact — the same idea has a ceiling on the inbound side and
none on the outbound, in the same crate.

ACTION:    add `const MAX_EGRESS_TOKEN_TTL_SECS: u64 = 86_400;` (or the operator-facing knob, if
one is wanted) in `egress_auth/mod.rs` beside `default_expires_in`, and clamp at the two mint
sites: `now.saturating_add(tok.expires_in.min(MAX_EGRESS_TOKEN_TTL_SECS))` at
`jwt_bearer.rs:228` and `oauth_client_credentials.rs:171`. Clamping at the mint (not in the
deserializer) keeps the wire-tolerance the deserializer is for, and keeps the ceiling in the same
place the hostile-input comment already sits.

### X-1013 · this slice owns 311 lines of the neutral crate's plane-vocabulary debt, against a spec clause that says ZERO
CLASS:     abi
CERTAINTY: VERIFIED
EVIDENCE:  `busbar-kernel` is `Family::Neutral` —
```
$ sed -n '285,289p' xtask/src/gates/kind_isolation.rs
    KindDef {
        kind: "kernel",
        family: Family::Neutral,
        matchers: &["=busbar-kernel", "busbar-kernel-"],
    },
```
`BUSBAR-1.6.0.md` Part 0, "What done means", clause 2: *"every `Family::Neutral` crate names ZERO
plane/control/transport/dialect instance vocabulary in source, ceiling 0 and ARMED, with no ratchet
row able to raise it."* The ceilings are not 0:
```
$ sed -n '21,27p' qa/plane-purity-strict.toml
[categories]
PATH-INCLUDE = 0
SYMBOL = 61
TYPE = 13
KEY = 377
DIALECT = 456
BACKWARDS = 33
```
A comment-stripped scan of the 154 slice files against the scanner's own alternations
(`scanner.rs:29` `["llm","mcp","a2a","voice"]`, `:44` the six dialects, `:65`/`:76` the
CamelCase/SCREAMING prefixes) finds **314 code lines in 23 files** — 3 in production
(`config/mod.rs`, raised separately as X-1002 and carrying `plane-purity: frozen-wire` waivers)
and **311 in test scope**. Positive control: the identical scan over `src/config/tests/tests.rs`
returns 4, so the 131 zero files are measurements. Heaviest:
```
 111  crates/busbar-kernel/src/auth/tests/tests.rs
  83  crates/busbar-kernel/src/config_validate/tests/tests.rs
  18  crates/busbar-kernel/src/failover/tests/failover_tests.rs
  16  crates/busbar-kernel/src/hooks/tests/gate_tests.rs
  13  crates/busbar-kernel/src/governance/tests/signing_tests.rs
   8  crates/busbar-kernel/src/audit/tests/boot_verify_golden.rs
   8  crates/busbar-kernel/src/config_validate/tests/secret_ref_coverage.rs
   8  crates/busbar-kernel/src/egress_auth/tests/prebuilt_auth_tests.rs
   7  crates/busbar-kernel/src/handlers/tests/registry_tests.rs
```
The gate is NOT blind here — `plane_purity::measure` walks the neutral roots with
`WalkSpec::new(present).ext("rs")` and no `.exclude()`, and scans `Scope::Production` and
`Scope::Test` separately (`plane_purity/mod.rs:168-186`), and the selftest plants into
`crates/busbar-kernel/src/tests/` on purpose (`mod.rs:971-975`). The debt is measured, reported and
ratcheted. It is simply not ZERO, and clause 2 says it must be before 1.6.0 ships.

Scope note: 311 of 940 total test-scope hits (the sum of the six ceilings) sit in this slice, so
this is roughly a third of the neutral-crate debt for the whole workspace. The other half of
`busbar-kernel` is S02's and the remainder is spread across the other neutral crates.

ACTION:    PARK for the owner — this is a scheduling call, not an edit an agent makes. The
mechanical part is real though: the two heaviest files (`auth/tests/tests.rs` 111,
`config_validate/tests/tests.rs` 83 = 62% of this slice's debt) are where the drain pays for
itself. Both name plane keys as literal config-section strings and audience URIs in fixtures; both
can take the same treatment the production side already uses — a neutral fixture constant, or
`plane::config::NAMED_MAP_SECTIONS`-style indirection — without weakening what they assert. Do NOT
lower the `qa/plane-purity-strict.toml` ceilings to match a partial drain; lower them only after
the measurement drops.


## TALLY
```
files in slice:  154     (equals `wc -l .sweep/S01-kernel-a.txt`)
verdict lines:   154
CLEAN:           61
FINDING:         92      rows raised: 14 (X-1000 .. X-1013)
DELETABLE:       1
UNREADABLE:      0
```

### Rows by class and certainty
```
auth              X-1001  VERIFIED    the mint ceiling binds POST /keys only, not POST /auth/token
auth              X-1012  VERIFIED    outbound token TTL has no ceiling; the inbound twin has one
config            X-1000  VERIFIED    auth.policy.default_ttl is validated and never read
abi               X-1002  VERIFIED    core names McpEndpointSection / deploy.mcp in production code
abi               X-1013  VERIFIED    311 test-scope plane-vocab lines against a "ceiling 0" clause
instrument-blind  X-1003  VERIFIED    plane identity laundered through NAMED_MAP_SECTIONS[2]/[3]
instrument-blind  X-1006  VERIFIED    pool_upstream_creds bench: 0 assertions, subject left the crate
instrument-blind  X-1008  ADJUDICATE  admin_witness's rationale is false where the ledger now lives
missing-code      X-1009  VERIFIED    audit_ring::list_filtered ships with zero callers
missing-code      X-1010  VERIFIED    ingress/path_ingress.rs is a shim to a deleted destination
drift             X-1004  VERIFIED    185 references to 5 deleted crates across 73 slice files
drift             X-1005  VERIFIED    broken intra-doc links to crate::ir::variant
drift             X-1007  VERIFIED    bench documents `cargo bench -p busbar-core`
drift             X-1011  VERIFIED    RefuseSecondLookup documented as production, is test-only
```

## WHAT THIS SLICE PROVES ABOUT FILES OUTSIDE IT — reported, NOT acted on

**1. `plane-purity`'s BACKWARDS rule cannot produce a NO. Its subject left the tree.**
This is the most serious thing the slice turned up, and it is in S03/S16's files.
```
$ sed -n '223,225p' xtask/src/gates/plane_purity/scanner.rs
            let reach = path_of(&code, "busbar_core")
                || extern_crate_of(&code, "busbar_core")
                || bound_as(&code, "busbar_core");
```
`path_of` (`:450-460`) requires the crate name to be followed, modulo spaces, by `::`.
```
$ git grep -n "busbar_core" -- 'crates/busbar-llm/**/*.rs' 'crates/busbar-mcp/**/*.rs'                                'crates/busbar-a2a/**/*.rs' 'crates/busbar-voice/**/*.rs'
crates/busbar-a2a/src/a2a/tests/adminverbs_tests.rs:50:    busbar_core_admin::install();
crates/busbar-mcp/src/mcp/tests/adminverbs_tests.rs:43:    busbar_core_admin::install();
```
Two hits, both `busbar_core_admin` — after `busbar_core` the tail is `_admin::`, which does not
start with `::`, so `path_of` does not match. **The rule matches zero lines in the whole plane
population.** The reach it exists to measure is now spelled `busbar_kernel::`:
```
$ git grep -c "busbar_kernel::" -- 'crates/busbar-llm/**' 'crates/busbar-mcp/**'                                    'crates/busbar-a2a/**' 'crates/busbar-voice/**' | awk -F: '{s+=$2;n++} END{print n, s}'
244 2561
```
2,561 lines across 244 files. Downstream, the ratchets over that zero are fiction:
`qa/plane-purity-strict.toml` `BACKWARDS = 33` and `[test-reach] llm = 24, mcp = 1, a2a = 3,
voice = 0`, whose own header (`:29-36`) cross-checks them against `qa/construction.toml`'s
`ports-only-tests:<crate>` (llm=565, mcp=1, a2a=3, voice=0) — so that measurement should be checked
for the same moved subject. Fix: `busbar_core` -> `busbar_kernel` at `scanner.rs:223-225`, then
RE-MEASURE before touching a single ceiling. Expect every BACKWARDS number to jump; that is the
gate starting to work, not a regression.

**2. `crates/busbar-kernel/src/state.rs:597`** carries `[`App::pool_upstream_creds`]` as an
intra-doc link. No such method exists in this crate (X-1006 evidence) — it is
`EngineTables::pool_upstream_creds`, in `busbar-llm`. Same broken-link class as X-1005.

**3. `crates/busbar-kernel/benches/plane_host_vtable_perf.rs:45`** carries the identical
`cargo bench -p busbar-core` line that X-1007 raises for its sibling.

**4. Twelve further `NAMED_MAP_SECTIONS[2]`/`[3]` positional indices** live in
`crates/busbar-kernel/src/appbuild.rs`, `src/config_validate/mod.rs`, `src/plane/config.rs` and
`tests/plane_integration.rs`. Fixing X-1003 in `config/mod.rs` alone leaves the laundering pattern
live in four other files.

**5. `crates/busbar-kernel/Cargo.toml`** declares
`openapi-schema = ["dep:schemars", "busbar-llm/openapi-schema", "busbar-mcp/openapi-schema",
"busbar-a2a/openapi-schema"]`, but those three crates appear only under `[dev-dependencies]`.
Enabling `openapi-schema` in a non-test build forwards to nothing that is in that build's graph.
Worth a manifest-slice check.

**6. The #39 one-crate-per-plane collapse has not landed.** `crates/busbar-mcp` AND
`crates/busbar-plane-mcp` are both workspace members; likewise a2a. `crates/busbar-llm-codec` and
`crates/busbar-voice-codec` are live members while #39 states "there is NO separate `busbar-*-codec`
crate", and #18 makes voice a dialect inside the streaming plane rather than its own crate
(`crates/busbar-voice` exists). S15/S17 territory.

**7. `crates/busbar-kernel/src/config_validate/tests/secret_ref_coverage.rs`** (in this slice,
verdict CLEAN — it carries a `body.len() > 500` floor and panics on a missing marker, so it fails
closed) hard-codes source paths to `crates/busbar-mcp` and `crates/busbar-a2a` for its
`PlaneCfg::secret_refs` destructure scan (`:302-318`). It is therefore a TWO-PLANE instrument: a
`streaming` or `decisions` plane that grows a `SecretRef`-bearing config section is not scanned, and
nothing makes that absence visible.
