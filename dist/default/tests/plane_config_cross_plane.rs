// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod linked;

use busbar_kernel::config::plane_sections::config_sections;

fn register_planes() {
    linked::install();
}

fn refusal_for(section: &str, hook: &str) -> String {
    let yaml = format!(
        "providers: {{}}\nmodels: {{}}\n{section}:\n  x:\n    url: \"https://vendor.example/x\"\n    pin: {{ mechanism: unpinned }}\n    hooks: [\"{hook}\"]\n"
    );
    let errors: Vec<String> = match busbar_kernel::config::deploy_from_yaml_str(&yaml) {
        Err(e) => vec![e.to_string()],
        Ok(deploy) => busbar_kernel::config::resolve(&deploy, &std::collections::HashMap::new())
            .err()
            .unwrap_or_default(),
    };
    errors
        .into_iter()
        .find(|e| e.contains(hook))
        .unwrap_or_else(|| panic!("the `{section}:` plane must refuse `{hook}`"))
}

#[test]
fn every_section_the_grammar_declares_is_refused_on_both_planes() {
    register_planes();

    let agents = linked::owning("agents").config_section;
    let tools = linked::owning("tools").config_section;
    for section in config_sections() {
        let hook = format!("{section}.some-hook");

        let on_agents = refusal_for(agents, &hook);
        let on_tools = refusal_for(tools, &hook);

        let agents_body = on_agents
            .split_once(&format!("`{agents}.x`"))
            .map(|(_, body)| body)
            .expect("the `agents:` plane keeps its own wording for WHERE");
        let tools_body = on_tools
            .split_once(&format!("`{tools}.x`"))
            .map(|(_, body)| body)
            .expect("the `tools:` plane keeps its own wording for WHERE");
        assert_eq!(
            agents_body, tools_body,
            "one rule, one sentence: the planes may differ only in the site they name"
        );
        assert!(
            agents_body.contains(&format!("reaches onto the `{section}:` plane")),
            "the refusal must NAME the section reached onto, got: {on_agents}"
        );
    }
}
