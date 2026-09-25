THE ALL-GREEN FIXTURE for `cargo xtask gate reachability`.

The same five planes as the all-red fixture next door, fully wired: every plane registered — a row
of the manifest's linked table (`crates/busbar/Cargo.toml`) that `register_planes()` folds over
`LINKED`, and a plane type in `plane_claims()` — and every plane given a LIVE UNIT PATH, both kinds:
llm, mcp, a2a and streaming through the #28 rider (`root/gauntlet_install.rs` flips each key onto a
runner in `root/gauntlet_kernel.rs` that builds a `Units` type, and `main.rs` calls `install()`),
decision through a `Units` impl its linked entry (`root/plane_decision.rs`, the manifest's
`linked-entry` row) builds in `PLANE_HOOKS`. Every `root/*.rs` module is reached from `fn main()`.
The self-test breaks each link in turn — a key never flipped, a flip in test scope, a runner that
builds no unit, an install nobody calls, flips in an uncalled function whose name collides with a
reached one, an entry that exports no unit — and plants a plugin crate's `linked` module and a fold
over `LINKED` to prove both are read.

It is the control without which every RED case in the self-test is satisfiable by a gate that is
simply red about everything. It also carries the DECLARED/UNDECLARED pair: the self-test takes the
decision plane's unit path away twice, once with `[[dormant]]` rows in `qa/reachability.toml` and
once without, and the two cases differ in nothing else.
