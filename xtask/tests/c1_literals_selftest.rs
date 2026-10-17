//! c1-literals' self-test, driven through the dispatcher under `cargo test` (no other check runs a
//! gate's battery): every planted literal, the inner line of a continued one included, goes RED
//! naming its word, and the masked strings and prose stay green.

#[test]
fn c1_literals_proves_red_in_its_selftest() {
    let args = vec![
        "gate".to_string(),
        "c1-literals".to_string(),
        "--selftest".to_string(),
    ];
    assert_eq!(xtask::cli::main(&args), 0);
}
