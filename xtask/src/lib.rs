//! `xtask` — the workspace's own gate runner.
//!
//! THE ONE RULE THAT SHAPES THIS CRATE: **xtask reads the tree as TEXT.** It depends on no
//! `busbar-*` crate and never will; a gate that `use`s the type it is auditing is a gate whose
//! verdict moves when the type does. `cargo xtask gate segregation` enforces that in both
//! directions — nothing here imports a product crate, and nothing in the tree imports this.
//!
//! The public surface a gate conversion consumes:
//!
//! * [`ctx::Ctx`] — the tree, read through one place: [`ctx::WalkSpec`] (sorted, floor-checked,
//!   missing-root-checked), `read`/`exists` (overlay-aware), `git`, `run_checked`, `cargo_metadata`.
//! * [`ledger`] — [`ledger::Row`]/[`ledger::Status`] in the shape `release-gate/lib.sh::record`
//!   writes, and [`ledger::Reconcile`], which turns the owed set into a refusal.
//! * [`gates::Gate`] — `run` + `selftest`, plus [`gates::prove_red`]/[`gates::prove_green`], the
//!   only handle a selftest gets onto its gate.
//! * [`scan`], [`planes`], [`yaml_lite`], [`gitp`], [`toml_lite`] — the shared readers, one copy
//!   each, replacing the idioms the shell re-implemented per script.
//! * [`parity`] — run the legacy script and the Rust gate over the same tree and require identical
//!   rows, before any Python or bash is deleted.

pub mod cli;
pub mod ctx;
pub mod denylist;
pub mod gates;
pub mod gitp;
pub mod ledger;
pub mod parity;
pub mod planes;
pub mod scan;
pub mod selftest;
pub mod toml_lite;
pub mod yaml_lite;
