THE ALL-GREEN FIXTURE for `cargo xtask gate reachability`.

The same five planes as the all-red fixture next door, fully wired: every plane registered in
`register_planes()`/`plane_claims()`, every `root/*.rs` module reached from `fn main()` through a
chain of real calls, and every `Units` type built inside a function that chain arrives at.

It is the control without which every RED case in the self-test is satisfiable by a gate that is
simply red about everything. It also carries the DECLARED/UNDECLARED pair: the self-test plants a
dormant `units_a2a.rs` over it twice, once with a `[[dormant]]` row in `qa/reachability.toml` and
once without, and the two cases differ in nothing else.
