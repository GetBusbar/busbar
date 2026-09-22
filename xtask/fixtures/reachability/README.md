THE ALL-RED FIXTURE for `cargo xtask gate reachability`.

Every failure shape this gate knows, in one tiny tree, so that no self-test case has to plant into
the real crate and re-scan it (the "grew a whole-tree scan per plant" regression the selftest
budget exists to catch).

  * `register_planes()` / `plane_claims()` have EMPTY bodies   -> five `registered:` rows RED.
  * `main.rs` reaches no `root::units_*` module                -> five `root-reach:` rows RED.
  * each `units_<x>.rs` declares a `Units` type whose only
    construction sites are its own constructor and a test file -> five `unit-path:` rows RED.
  * `money_book.rs` is declared by `root/mod.rs` and named
    nowhere else                                               -> `root-module` RED.
  * `units_orphan.rs` maps to no roster plane                  -> `roster` RED.
  * `qa/reachability.toml` declares a subject on no roster     -> `stale-declaration` RED.

It is NOT a copy of the real crate and must not become one: its whole value is that it is small
enough to read in one screen and cheap enough to run twenty times. The real red-before-green proof
is `cargo xtask gate reachability` over this repository.
