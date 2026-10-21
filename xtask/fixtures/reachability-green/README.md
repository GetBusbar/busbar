THE ALL-GREEN FIXTURE for `cargo xtask gate reachability`.

The same five planes as the all-red fixture next door, fully wired: every plane registered — a row
of the manifest's linked table (`crates/busbar/Cargo.toml`) that `register_planes()` folds over
`LINKED`, and a plane type in `plane_claims()` — and every plane given a LIVE UNIT PATH, both kinds:
llm, mcp and a2a through a `Units` impl their plugin crate's `linked` entry builds in `PLANE_HOOKS`,
streaming through its served door (`root/serve.rs`), and decision through a `Units` impl its linked
entry inside the root (`root/plane_decisions.rs`, the manifest's `linked-entry` row) builds in
`PLANE_HOOKS`. Every `root/*.rs` module is reached from `fn main()`. The self-test breaks each link
in turn — an entry gone, an entry whose type is no `Units` impl, a `Units` impl no exported item
builds, a door with no data route, no door row, two compositions — and every plane in turn on the
all-red fixture. (The #28 kernel-loop rider these planes once rode is deleted with the kernel's
runner table, status row 82, D2.)

It is the control without which every RED case in the self-test is satisfiable by a gate that is
simply red about everything. It also carries the DECLARED/UNDECLARED pair: the self-test takes the
decision plane's unit path away twice, once with `[[dormant]]` rows in `qa/reachability.toml` and
once without, and the two cases differ in nothing else.

It also carries the five plane-kind crates the real tree does (`crates/busbar-plane-*`, a manifest and
a `src/lib.rs` each), so `reachability:plane-crates` has a census to read: four map to their roster
plane by the key their `impl PlaneMeta` declares, and `busbar-plane-mcp` declares none and maps as the
mcp row's linked crate. The self-test plants a sixth plane crate the roster does not name, a crate
mapped by its name alone, and a tree with none — each RED.

Its root `Cargo.toml` is the manifest the plane-crates row reads for the planes the root PINS
(#935); it pins none, because all five plane crates are laid under `crates/` here.
