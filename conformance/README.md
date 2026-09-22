# conformance/

The conformance-claim manifest home (`CONFORMANCE-SYNC-DESIGN.md` §3.1).

## Status (2026-09-19)

- `registry.toml` — LANDED. The hand-authored suite registry
  (`CONFORMANCE-SYNC-DESIGN.md` §3.3): standard, plan, tier ceiling, free/paid
  cost classification, verdict artifact name, per suite. Holds no status.
- `manifest.json` — NOT YET GENERATED. Written only by
  `cargo xtask conformance-manifest --write` (§3.2), which is NOT YET BUILT.
  Until that xtask subcommand and its `xtask conformance check --suite <id>`
  companion land, the `busbar-release-turnstile` `conformance::conformance_checks`
  `CommandCheck`s that shell to `cargo xtask conformance check --suite <id>`
  will fail closed (non-zero exit / could-not-spawn) — the correct deny-safe
  default for an unimplemented check, not a silent pass.

## What still needs building (tracked, not done here)

1. `cargo xtask conformance check --suite <id>` — reads `manifest.json`,
   exits 0 iff that suite's row is `status:"pass"` for the exact candidate
   SHA (freshness per §5.2). The turnstile side already shells to this.
2. `cargo xtask conformance-manifest --write` — the generator (§3.2):
   downloads `conformance-verdict-<suite>` artifacts, reconciles against
   `registry.toml` (owed vs got, §3.2 step 3), applies staleness (§5.2),
   writes `manifest.json`.
3. `cargo xtask render-conformance --write` — renders the README badge block
   and the website certifications-page claim block from `manifest.json`
   (§6.1/§6.2).
4. The `conformance:*` xtask gate rows (§5): `registry`, `manifest-drift`,
   `coverage`, `readme-drift`, `page-drift`, `freshness`, `no-orphan-claim`.
5. The four NOT-built harnesses themselves (Autobahn/h2spec/testssl/
   slsa-verifier) and their `<name>-conformance.yml` workflows
   (`CONFORMANCE-GATES-PLAN.md` §5).

See `CONFORMANCE-GATES-PLAN.md`, `CONFORMANCE-SYNC-DESIGN.md`, and
`CONFORMANCE-MATRIX-RULING.md` for the full grounding. The turnstile/train
gate wiring that CONSUMES this manifest is landed in the `busbar-release`
repo (`crates/busbar-release-turnstile/src/conformance.rs`,
`crates/busbar-release-turnstile/src/auto_apply.rs`,
`crates/busbar-release-train/src/conformance.rs`).
