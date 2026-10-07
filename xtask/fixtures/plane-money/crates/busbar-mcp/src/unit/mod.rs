// FIXTURE: the declaring module. `money.rs` is production and must flag; `oracle_double.rs` is
// declared under `#[cfg(test)]` with a `#[path]`, so it is TEST SCOPE and must not.
pub mod money;

#[cfg(test)]
#[path = "oracle_double.rs"]
mod oracle_double;
