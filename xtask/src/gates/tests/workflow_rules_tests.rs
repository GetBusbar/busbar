// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn both_yaml_spellings_of_a_tag_trigger_are_caught() {
    assert!(has_v_star_tag_trigger(
        "on:\n  push:\n    tags:\n      - \"v*\"\n"
    ));
    assert!(has_v_star_tag_trigger("on:\n  push:\n    tags: [\"v*\"]\n"));
    assert!(has_v_star_tag_trigger("on:\n  push:\n    tags: v*\n"));
    assert!(!has_v_star_tag_trigger(
        "on:\n  push:\n    branches: [main]\n"
    ));
}

#[test]
fn a_refspec_destination_is_read_from_either_side() {
    assert_eq!(
        refspec_destination("git push origin main:main").as_deref(),
        Some("main")
    );
    assert_eq!(
        refspec_destination("git push origin \"HEAD:refs/heads/proof-manifests\"").as_deref(),
        Some("proof-manifests")
    );
    assert_eq!(
        refspec_destination("git push origin \"HEAD:${VERSION}\"").as_deref(),
        Some("${VERSION}")
    );
}

#[test]
fn a_bare_release_branch_push_is_caught_but_a_lookalike_is_not() {
    assert!(pushes_bare_release_branch("git push origin main"));
    assert!(pushes_bare_release_branch("git push origin qa"));
    assert!(!pushes_bare_release_branch("git push origin main-docs"));
    assert!(!pushes_bare_release_branch("git push origin main:main"));
}

#[test]
fn git_push_is_found_through_a_dash_c() {
    assert!(contains_git_push("run: git push origin x"));
    assert!(contains_git_push("git -C \"$pub\" push origin y"));
    assert!(!contains_git_push("echo pushing"));
    assert!(!contains_git_push("legit pushback"));
}

#[test]
fn only_a_statement_counts_as_an_attestation_verify() {
    assert!(is_attestation_verify_statement("  gh attestation verify x"));
    assert!(is_attestation_verify_statement(
        "  if ! gh attestation verify x; then"
    ));
    assert!(!is_attestation_verify_statement(
        "  echo 'run gh attestation verify yourself'"
    ));
}

#[test]
fn a_signer_value_stops_at_shell_punctuation() {
    assert_eq!(
        signer_value("gh attestation verify x --signer-workflow a/b.yml; then").as_deref(),
        Some("a/b.yml")
    );
    assert_eq!(
        signer_value("--signer-workflow=\"a/b.yml\"").as_deref(),
        Some("a/b.yml")
    );
    assert_eq!(signer_value("gh attestation verify x --repo o/r"), None);
}

#[test]
fn a_pin_is_a_forty_hex_sha_and_nothing_else() {
    assert!(is_sha40("398d4b0eeef1380460a10c8013a76f728fb906ac"));
    assert!(!is_sha40("v3"));
    assert!(!is_sha40("398D4B0EEEF1380460A10C8013A76F728FB906AC"));
}

#[test]
fn a_uses_line_yields_its_reference_and_its_trailing_tag_comment() {
    assert_eq!(
        parse_uses("      - uses: actions/checkout@abc # v7"),
        Some(("actions/checkout@abc".into(), Some("# v7".into())))
    );
    assert_eq!(
        parse_uses("      uses: ./.github/workflows/docker.yml"),
        Some(("./.github/workflows/docker.yml".into(), None))
    );
    assert_eq!(parse_uses("      run: cargo test"), None);
}

#[test]
fn a_flow_style_step_yields_its_reference_and_the_comment_after_its_brace() {
    assert_eq!(
        parse_uses("      - { uses: actions/checkout@abc, with: { ref: x } } # v4"),
        Some(("actions/checkout@abc".into(), Some("# v4".into())))
    );
    assert_eq!(
        parse_uses(
            "      - { if: always(), uses: actions/upload-artifact@abc, with: { name: n } }"
        ),
        Some(("actions/upload-artifact@abc".into(), None))
    );
    // `uses:` that is not a key of the mapping (inside a string) is not an action reference.
    assert_eq!(
        parse_uses("      - { run: \"echo uses: nothing\", id: x }"),
        None
    );
    assert_eq!(parse_uses("      - { id: pre, run: bash x.sh }"), None);
}

#[test]
fn r14_reads_uses_out_of_a_composite_action_too_not_only_workflows() {
    // THE RED PLANT for the widened scope: `.github/actions` does not exist in the real tree,
    // so this plants one via overlay and proves R14 finds it anyway (`has_composite_actions`
    // is exactly what makes that legitimate rather than a MissingRoot). A floating tag inside
    // `runs.steps` is the identical exposure a workflow's `uses:` carries, and before this
    // widening it would have scanned clean forever, from the day the first composite action
    // landed, having never been proven to look.
    let cx = Ctx::workspace().expect("workspace context");
    let mut ov = Overlay::new();
    ov.set(
        format!("{ACTIONS_DIR}/example/action.yml"),
        "runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v7\n",
    );
    let cx = cx.with_overlay(ov);
    let findings = check(&cx).expect("check runs over the overlay");
    assert!(
        findings
            .iter()
            .any(|f| f.rule == "R14" && f.message.contains(".github/actions/example/action.yml")),
        "R14 did not flag the floating tag inside the planted composite action: {:?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>()
    );
}

#[test]
fn a_composite_action_pinned_to_a_sha_with_its_tag_comment_is_silent() {
    // The GREEN twin: the same shape, correctly pinned, must not fire.
    let cx = Ctx::workspace().expect("workspace context");
    let mut ov = Overlay::new();
    ov.set(
        format!("{ACTIONS_DIR}/example/action.yml"),
        "runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\n",
    );
    let cx = cx.with_overlay(ov);
    let findings = check(&cx).expect("check runs over the overlay");
    assert!(
        !findings
            .iter()
            .any(|f| f.message.contains(".github/actions/example/action.yml")),
        "a correctly pinned composite action must not be flagged: {:?}",
        findings.iter().map(|f| &f.message).collect::<Vec<_>>()
    );
}

#[test]
fn the_gate_is_green_over_the_real_tree() {
    let cx = Ctx::workspace().expect("workspace context");
    let verdict = crate::gates::execute(&WorkflowRulesGate, &cx);
    assert!(
        !verdict.red,
        "workflow-rules is RED over the real tree: {:?}",
        verdict.problems
    );
}

#[test]
fn every_rule_is_proven_able_to_go_red() {
    let cx = Ctx::workspace().expect("workspace context");
    let gate = WorkflowRulesGate;
    let report = gate.selftest(&cx);
    crate::gates::verify_report(&gate, &report).expect("every rule proven RED");
}

/// A two-job workflow: `slsa-build` (under `BUILDER_IF`) uploads the release artifact, and a shard
/// downloads it from its own run under `STEP_IF`, in the block spelling promote.yml uses.
const R17_FIXTURE: &str = "on: [pull_request, merge_group]
jobs:
  slsa-build:
    if: BUILDER_IF
    steps:
      - run: cargo build --release
      - { uses: actions/upload-artifact@abc, with: { name: \"slsa-artifact-x\", path: slsa/ } } # v7
  hop-shard:
    steps:
      - if: STEP_IF
        uses: actions/download-artifact@abc # v8
        with: { name: \"slsa-artifact-x\", path: slsa }
      - run: ci hop
";

fn r17(builder_if: &str, step_if: &str) -> Vec<String> {
    let text = R17_FIXTURE
        .replace("BUILDER_IF", builder_if)
        .replace("STEP_IF", step_if);
    release_artifact_findings("promote.yml", &text)
        .into_iter()
        .map(|f| {
            assert_eq!(f.rule, "R17");
            f.message
        })
        .collect()
}

const NEEDS_ARTIFACT: &str = "needs.preflight.outputs.needs_release_artifact == 'true'";

#[test]
fn r17_a_merge_group_only_build_under_a_pull_request_download_is_red() {
    // #740 exactly: the builder runs only in a merge group, the download whenever the rung reads it.
    let got = r17(
        "github.event_name == 'merge_group' && needs.preflight.outputs.run == '1'",
        NEEDS_ARTIFACT,
    );
    assert_eq!(got.len(), 1, "{got:?}");
    assert!(
        got[0].contains("`hop-shard`") && got[0].contains("`slsa-build`"),
        "{got:?}"
    );
    // The same narrowing written as a base-branch test is the same red.
    assert_eq!(r17("github.base_ref == 'qa'", NEEDS_ARTIFACT).len(), 1);
}

#[test]
fn r17_a_builder_that_admits_the_download_condition_is_green() {
    let fixed = format!(
        "needs.preflight.outputs.run == '1' && (github.event_name == 'merge_group' || {NEEDS_ARTIFACT})"
    );
    assert!(r17(&fixed, NEEDS_ARTIFACT).is_empty());
    // Wrapped in `${{ }}` the same.
    assert!(r17(&format!("${{{{ {fixed} }}}}"), NEEDS_ARTIFACT).is_empty());
    // A builder narrowed only by the run gate, not by event, runs wherever the run runs.
    assert!(r17("needs.preflight.outputs.run == '1'", NEEDS_ARTIFACT).is_empty());
}

#[test]
fn r17_a_download_that_waits_on_the_builders_success_is_green() {
    // The soak's spelling: it downloads only after slsa-build succeeded, else builds its own.
    assert!(r17(
        "github.event_name == 'merge_group'",
        "needs.slsa-build.result == 'success'"
    )
    .is_empty());
}

#[test]
fn r17_an_unconditional_download_under_an_event_narrowed_builder_is_red() {
    let text = R17_FIXTURE
        .replace("BUILDER_IF", "github.event_name == 'merge_group'")
        .replace("      - if: STEP_IF\n        uses:", "      - uses:");
    assert_eq!(release_artifact_findings("promote.yml", &text).len(), 1);
}

#[test]
fn r17_a_download_with_no_builder_in_the_run_is_red_and_a_run_id_download_is_not_judged() {
    let orphan = R17_FIXTURE
        .replace("BUILDER_IF", "github.event_name == 'merge_group'")
        .replace("actions/upload-artifact@abc", "actions/cache@abc")
        .replace("STEP_IF", NEEDS_ARTIFACT);
    let got = release_artifact_findings("promote.yml", &orphan);
    assert_eq!(got.len(), 1);
    assert!(got[0]
        .message
        .contains("no job of this workflow uploads it"));
    // Another run's artifact (by run-id) is not this run's to build.
    let other = orphan.replace(
        "with: { name: \"slsa-artifact-x\", path: slsa }",
        "with: { name: \"slsa-artifact-x\", path: slsa, run-id: \"${{ env.RUN }}\" }",
    );
    assert!(release_artifact_findings("promote.yml", &other).is_empty());
}

#[test]
fn r17_a_flow_step_condition_is_read_up_to_the_next_key() {
    assert_eq!(
        step_condition(&["      - { if: always(), uses: actions/upload-artifact@abc }"]).as_deref(),
        Some("always()")
    );
    assert_eq!(
        step_condition(&["      - { uses: a@b, if: \"${{ x == 'y' }}\", with: { n: 1 } }"])
            .as_deref(),
        Some("x == 'y'")
    );
    assert_eq!(step_condition(&["      - run: true"]), None);
}

#[test]
fn r17_the_mutation_anchor_rewrites_only_the_named_jobs_if() {
    let t = "jobs:\n  a:\n    if: one\n  slsa-build:\n    if: two\n    needs: a\n";
    assert_eq!(
        reif_job(t, "slsa-build", "three"),
        "jobs:\n  a:\n    if: one\n  slsa-build:\n    if: three\n    needs: a\n"
    );
    assert_eq!(reif_job(t, "absent", "three"), t);
}

const ENGINE_VAR_JOB: &str = "env:\n  SHA: x\njobs:\n  pre:\n    env: { RELEASE_REF: \"${{ vars.ENGINE_REF }}\", ENGINE_SHA256: \"${{ vars.ENGINE_SHA256 }}\" }\n    steps:\n      - name: Engine\n        run: |\n          [[ \"$RELEASE_REF\" =~ ^[0-9a-f]{40}$ ]] || { echo bad; exit 1; }\n          name=\"busbar-release-ci-linux-x86_64-$RELEASE_REF\"\n          echo \"$ENGINE_SHA256  bin\" | sha256sum -c -\n      - { uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1, with: { repository: GetBusbar/busbar-release, ref: \"${{ env.RELEASE_REF }}\", path: busbar-release } } # v7\n";

fn r16(text: &str) -> Vec<String> {
    engine_pin_findings("w.yml", text)
        .into_iter()
        .map(|f| f.message)
        .collect()
}

#[test]
fn r16_accepts_the_variable_pin_with_its_shape_check_and_its_sha256() {
    assert_eq!(r16(ENGINE_VAR_JOB), Vec::<String>::new());
}

#[test]
fn r16_accepts_an_in_file_sha_pin() {
    let t = "jobs:\n  a:\n    steps:\n      - { uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1, with: { repository: GetBusbar/busbar-release, ref: 7ab21912d664d11c7df6cc98fe78eed6b0119177 } } # v7\n";
    assert_eq!(r16(t), Vec::<String>::new());
    // and through a workflow-level env var holding the literal
    let t = "env:\n  RELEASE_REF: 7ab21912d664d11c7df6cc98fe78eed6b0119177\njobs:\n  a:\n    steps:\n      - { uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1, with: { repository: GetBusbar/busbar-release, ref: \"${{ env.RELEASE_REF }}\" } } # v7\n";
    assert_eq!(r16(t), Vec::<String>::new());
}

#[test]
fn r16_refuses_a_branch_or_a_tag_ref() {
    // RED: the checkout at a branch.
    let t = ENGINE_VAR_JOB.replace("ref: \"${{ env.RELEASE_REF }}\"", "ref: dev");
    assert!(r16(&t).iter().any(|m| m.contains("`dev`")), "{:?}", r16(&t));
    // RED: the variable is defined as a tag.
    let t = ENGINE_VAR_JOB.replace(
        "RELEASE_REF: \"${{ vars.ENGINE_REF }}\"",
        "RELEASE_REF: v1.6.0",
    );
    assert!(
        r16(&t).iter().any(|m| m.contains("v1.6.0")),
        "{:?}",
        r16(&t)
    );
    // RED: in-file, but a tag at the workflow level.
    let t = "env:\n  RELEASE_REF: refs/tags/v1\njobs:\n  a:\n    steps:\n      - { uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1, with: { repository: GetBusbar/busbar-release, ref: \"${{ env.RELEASE_REF }}\" } } # v7\n";
    assert!(!r16(t).is_empty());
    // RED: no ref at all (the default branch).
    let t = "jobs:\n  a:\n    steps:\n      - { uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1, with: { repository: GetBusbar/busbar-release } } # v7\n";
    assert!(r16(t).iter().any(|m| m.contains("no `ref:`")));
}

#[test]
fn r16_refuses_a_variable_pin_without_its_shape_check_or_its_sha256() {
    let t = ENGINE_VAR_JOB.replace("=~ ^[0-9a-f]{40}$", "!= \"\"");
    assert!(
        r16(&t).iter().any(|m| m.contains("default branch")),
        "{:?}",
        r16(&t)
    );
    let t = ENGINE_VAR_JOB.replace("sha256sum -c -", "cat");
    let got = r16(&t);
    assert_eq!(
        got.len(),
        2,
        "the download and the pin both name the missing check: {got:?}"
    );
    // The shape check AFTER the checkout guards nothing.
    let t = "jobs:\n  pre:\n    env: { RELEASE_REF: \"${{ vars.ENGINE_REF }}\" }\n    steps:\n      - { uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1, with: { repository: GetBusbar/busbar-release, ref: \"${{ env.RELEASE_REF }}\" } } # v7\n      - run: |\n          [[ \"$RELEASE_REF\" =~ ^[0-9a-f]{40}$ ]] || exit 1\n          echo \"$ENGINE_SHA256  b\" | sha256sum -c -\n";
    assert!(r16(t).iter().any(|m| m.contains("default branch")));
}

#[test]
fn a_key_value_is_read_whole_from_a_flow_mapping() {
    assert_eq!(
        key_value("{ repository: o/r, ref: \"${{ env.X }}\", path: p }", "ref").as_deref(),
        Some("${{ env.X }}")
    );
    assert_eq!(
        key_value("{ ref: dev, path: p }", "ref").as_deref(),
        Some("dev")
    );
    assert_eq!(key_value("{ prefref: dev }", "ref"), None);
    assert_eq!(env_ref("${{ env.RELEASE_REF }}"), Some("RELEASE_REF"));
    assert_eq!(env_ref("${{ vars.ENGINE_REF }}"), None);
}
