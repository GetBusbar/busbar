//! THE BLOCKING-FFI GATE'S RED PROOF, DRIVEN THROUGH THE DISPATCHER.
//!
//! The gate's self-test battery plants every shape the gate owes a finding for — the historical
//! inline plugin calls, a synchronous store call (`s.put_key(&k)?`) and a door seam the loader
//! grows, a deref-assignment line, `async unsafe fn` / `async extern "C" fn`, and a field-level
//! `#[cfg(test)]` before an async fn — and proves each RED, beside the green over the real tree.
//! No check runs a gate's self-test by itself, so this file is what holds the battery to exit 0
//! under `cargo test`.

fn run(args: &[&str]) -> i32 {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    xtask::cli::main(&owned)
}

#[test]
fn the_blocking_ffi_gate_proves_red_in_its_selftest() {
    assert_eq!(run(&["gate", "blocking-ffi", "--selftest"]), 0);
}
