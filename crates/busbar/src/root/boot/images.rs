// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! S2 admission owns the same image leases through parsing and instance construction.

use std::sync::Arc;

use busbar_kernel::config::grammar::PhaseOneIn;
use busbar_kernel::config::{Grammar, GrammarRefusal};
use busbar_plugin_abi::host_side::host_vt::HOST;
use busbar_plugin_loader::instance::{Ceilings, Images, ImagesBuilder};
use busbar_plugin_loader::process::ProcessResources;

pub(crate) struct FileImages {
    pub(crate) images: Images,
    pub(crate) aliases: Vec<(String, String)>,
    pub(crate) grammar: Grammar,
}

pub(crate) fn prepare(
    process: &ProcessResources,
    input: &PhaseOneIn<'_>,
) -> Result<FileImages, GrammarRefusal> {
    let mut plugins = input.plugins.clone();
    plugins.dir = input.dir.to_string_lossy().into_owned();
    for (name, version) in input.pins {
        plugins.min_versions.insert(name.clone(), version.clone());
        plugins
            .first_party_floors
            .insert(name.clone(), version.clone());
    }
    let admitted = crate::root::min3_boot::admit_images(&plugins).map_err(GrammarRefusal)?;
    let aliases = admitted
        .iter()
        .map(|(image, alias)| (image.identity().to_owned(), alias.clone()))
        .collect();
    let mut builder = ImagesBuilder::new(&HOST, Arc::clone(process.slots()), Ceilings::DEFAULT);
    for (image, _) in admitted {
        builder
            .admit(image)
            .map_err(|error| GrammarRefusal(error.to_string()))?;
    }
    let images = builder.finish();
    let mut linked: Vec<_> = busbar_kernel::preflight::linked_rows()
        .iter()
        .map(super::linked_row)
        .collect();
    linked.extend(super::linked_exports(crate::LINKED.export_doors).map_err(GrammarRefusal)?);
    let metadata = super::scanned_registry(linked, &plugins).map_err(GrammarRefusal)?;
    let grammar = crate::root::secret_grammar::of_images(
        &images,
        super::owners_of(&metadata),
        super::classify(&metadata, Some(&plugins)),
        super::skip_lines(metadata.skipped()),
    )
    .map_err(GrammarRefusal)?;
    Ok(FileImages {
        images,
        aliases,
        grammar,
    })
}
