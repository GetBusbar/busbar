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
//! * [`ere`] — a POSIX-ERE subset matcher, so the rule TABLES the shell drove its generic scanners
//!   with stay tables instead of becoming forty hand-written predicates nobody can diff against the
//!   row they came from.
//! * [`rx`] — the same idea one step further, for the rule cells that must READ what they matched:
//!   a backtracking engine with capture groups (named and numbered) over bytes. [`ere`] answers
//!   "does this line match"; `rx` answers "and what were the parts", which is what a ceilings table
//!   whose rows carry sub-expressions needs.
//! * [`toml_doc`] — a TOML reader that keeps the document's ORDER and its comments, for the gate
//!   whose ceilings file is edited by hand and whose `--write` arm must hand it back byte-identical
//!   apart from the numbers it moved.
//! * [`scan`], [`planes`], [`yaml_lite`], [`json_lite`], [`gitp`], [`toml_lite`] — the shared
//!   readers, one copy
//!   each, replacing the idioms the shell re-implemented per script.
//! * [`parity`] — run the legacy script and the Rust gate over the same tree and require identical
//!   rows, before any Python or bash is deleted.

pub mod audit;
pub mod audit_cmd;
pub mod cli;
pub mod ctx;
pub mod denylist;
pub mod discovery;
pub mod ere;
pub mod full_gate;
pub mod gates;
pub mod gitp;
pub mod json_lite;
pub mod ledger;
pub mod parity;
pub mod planes;
pub mod rx;
pub mod scan;
pub mod selftest;
pub mod sha256;
pub mod shipped;
pub mod toml_doc;
pub mod toml_lite;
pub mod yaml_lite;
