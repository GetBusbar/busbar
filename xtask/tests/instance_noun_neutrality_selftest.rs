//! THE INSTANCE-NOUN CENSUS PROVES ITS REDS UNDER `cargo test` (audit XG HIGH 3).
//!
//! `cargo xtask gate --all` judges the tree; it does not run a gate's selftest battery, so a plant
//! that would no longer bite is caught only where a test drives the battery. This drives the
//! census's battery: one red per noun (the linked plugin instances included) and the `:roster` row
//! derived from the composition root's manifest. The battery runs over the small fixture trees under
//! `xtask/fixtures/instance-noun*`, so it costs milliseconds, not a whole-tree scan per plant.

fn run(args: &[&str]) -> i32 {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    xtask::cli::main(&owned)
}

#[test]
fn the_instance_noun_neutrality_gate_proves_every_red_in_its_selftest() {
    assert_eq!(run(&["gate", "instance-noun-neutrality", "--selftest"]), 0);
}
