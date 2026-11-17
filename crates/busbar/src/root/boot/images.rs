// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! S2 admission owns the same image leases through parsing and instance construction.

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_kernel::config::grammar::PhaseOneIn;
use busbar_kernel::config::{Grammar, GrammarRefusal};
use busbar_plugin_abi::host_side::host_vt::HOST;
use busbar_plugin_loader::instance::{Ceilings, Images, ImagesBuilder};
use busbar_plugin_loader::process::ProcessResources;

#[derive(Clone)]
pub(crate) struct FileImages {
    pub(crate) images: Images,
    pub(crate) aliases: Vec<(String, String)>,
    pub(crate) grammar: Grammar,
    proofs: BTreeMap<String, ImageProof>,
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
    let mut linked: Vec<_> = busbar_kernel::preflight::linked_rows()
        .iter()
        .map(super::linked_row)
        .collect();
    linked.extend(super::linked_exports(crate::LINKED.export_doors).map_err(GrammarRefusal)?);
    // The read owns one capture: executable admission and grammar consume its exact bytes.
    let metadata = super::scanned_registry(linked, &plugins).map_err(GrammarRefusal)?;
    let admitted =
        crate::root::min3_boot::admit_images(&plugins, &metadata).map_err(GrammarRefusal)?;
    let proofs: BTreeMap<String, ImageProof> = admitted
        .iter()
        .map(|(image, _)| {
            (
                image.identity().to_owned(),
                ImageProof {
                    kind: image.kind(),
                    digest: image.sha256().copied(),
                },
            )
        })
        .collect();
    let aliases: Vec<(String, String)> = admitted
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
    let grammar = crate::root::secret_grammar::of_images(
        &images,
        super::owners_of(&metadata),
        super::classify(&metadata, Some(&plugins)),
        super::skip_lines(metadata.skipped()),
    )
    .map_err(GrammarRefusal)?;
    let grammar =
        with_http_instances(grammar, &aliases, &proofs, &images).map_err(GrammarRefusal)?;
    Ok(FileImages {
        images,
        aliases,
        grammar,
        proofs,
    })
}

#[derive(Clone, PartialEq, Eq)]
struct ImageProof {
    kind: busbar_plugin_abi::types::KindCode,
    // A linked image cannot be replaced within the running process.
    digest: Option<[u8; 32]>,
}

/// Immutable archive identities that already participate in the bootstrap or its grammar.
pub(crate) struct BootImages {
    proofs: BTreeMap<String, ImageProof>,
}

impl FileImages {
    /// Publish these images' secret grammar as the process's native secret axis (WP3 step 2): the one source of the
    /// secret words `--validate`, `--list-plugins`, the start grammar and every later read use. Called by the boot
    /// for the images it serves, never by a per-read phase one (which mutates nothing).
    pub(crate) fn publish_secrets(&self) {
        crate::root::native_secrets::NATIVE.publish_images(
            &self.grammar,
            self.proofs
                .iter()
                .filter(|(_, proof)| proof.digest.is_none())
                .map(|(identity, _)| identity.as_str()),
        );
    }

    /// Publish these images' hook facts (WP3 hook step): the one source config validation reads hook names,
    /// linkage and ranking words from. Called by the stage that prepares the images it serves or validates, never
    /// by a per-read phase one (which mutates nothing).
    pub(crate) fn publish_hooks(&self) {
        crate::root::hooks::NATIVE.publish_images(
            &self.images,
            &self.aliases,
            self.proofs
                .iter()
                .filter(|(_, proof)| proof.digest.is_none())
                .map(|(identity, _)| identity.as_str()),
        );
    }

    pub(crate) fn transport_images(&self) -> BTreeMap<String, Option<[u8; 32]>> {
        self.proofs
            .iter()
            .filter(|(_, proof)| proof.kind == busbar_plugin_abi::types::KindCode::Transport)
            .map(|(name, proof)| (name.clone(), proof.digest))
            .collect()
    }

    /// Preserve the admitted executable owners alongside the metadata from this same read.
    pub(crate) fn prepared_read(
        &self,
        input: &PhaseOneIn<'_>,
    ) -> Result<busbar_kernel::config::grammar::PreparedConfigRead, GrammarRefusal> {
        let planes = crate::root::min3_provider_plan::descriptors(self).map_err(GrammarRefusal)?;
        Ok(
            busbar_kernel::config::grammar::PreparedConfigRead::new(self.grammar.clone())
                .with_provider_planes(planes)
                .with_context(Arc::new(self.clone()))
                .for_input(input),
        )
    }

    /// Metadata comes from the same admitted image whose lease this read retains.
    pub(crate) fn plane_identity(
        &self,
        canonical: &str,
    ) -> Result<Arc<busbar_kernel::plane_driver::image_identity::PlaneImageIdentity>, String> {
        let proof = self
            .proofs
            .get(canonical)
            .filter(|proof| proof.kind == busbar_plugin_abi::types::KindCode::Plane)
            .ok_or_else(|| format!("plane `{canonical}` has no retained admitted image proof"))?;
        busbar_kernel::plane_driver::image_identity::PlaneImageIdentity::new(
            canonical.into(),
            proof.digest,
        )
        .map(Arc::new)
        .map_err(str::to_owned)
    }

    pub(crate) fn protect(
        &self,
        cfg: &busbar_kernel::config::RootCfg,
    ) -> Result<BootImages, String> {
        use busbar_plugin_abi::types::KindCode;
        let store = cfg
            .store
            .as_ref()
            .ok_or_else(busbar_kernel::config::store_required)?;
        let identity = self
            .images
            .identities()
            .find(|identity| self.images.names(identity).contains(&store.module.as_str()))
            .ok_or_else(|| "store.module has no admitted bootstrap image".to_owned())?;
        let proofs = self
            .proofs
            .iter()
            .filter(|(name, proof)| {
                name.as_str() == identity
                    || matches!(proof.kind, KindCode::Secret | KindCode::Transport)
            })
            .map(|(name, proof)| (name.clone(), proof.clone()))
            .collect();
        Ok(BootImages { proofs })
    }
}

impl BootImages {
    pub(crate) fn check(&self, candidate: &FileImages) -> Result<(), GrammarRefusal> {
        self.check_proofs(&candidate.proofs).map_err(GrammarRefusal)
    }

    fn check_proofs(&self, candidate: &BTreeMap<String, ImageProof>) -> Result<(), String> {
        for (name, proof) in &self.proofs {
            if candidate.get(name) != Some(proof) {
                return Err(format!(
                    "protected boot image {name} changed or was removed; restart required"
                ));
            }
        }
        for (name, proof) in candidate {
            if proof.kind == busbar_plugin_abi::types::KindCode::Secret
                && !self.proofs.contains_key(name)
            {
                return Err(format!("overlay-only image {name} contributes secret reference grammar; restart required"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod pin_tests {
    use super::*;
    use busbar_plugin_abi::types::KindCode;

    #[test]
    fn unchanged_grammar_does_not_authorize_replacing_its_image() {
        let old = ImageProof {
            kind: KindCode::Secret,
            digest: Some([1; 32]),
        };
        let held = BootImages {
            proofs: [("source".into(), old.clone())].into(),
        };
        assert!(held.check_proofs(&held.proofs).is_ok());
        let new = ImageProof {
            digest: Some([2; 32]),
            ..old
        };
        assert!(held.check_proofs(&[("source".into(), new)].into()).is_err());
        assert!(held.check_proofs(&BTreeMap::new()).is_err());
    }

    #[test]
    fn non_boot_plane_change_is_allowed_but_new_secret_grammar_is_not() {
        let held = BootImages {
            proofs: BTreeMap::new(),
        };
        let plane = ImageProof {
            kind: KindCode::Plane,
            digest: Some([2; 32]),
        };
        assert!(held.check_proofs(&[("plane".into(), plane)].into()).is_ok());
        let secret = ImageProof {
            kind: KindCode::Secret,
            digest: Some([3; 32]),
        };
        assert!(held
            .check_proofs(&[("source".into(), secret)].into())
            .is_err());
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "../tests/read_inventory.rs"]
mod read_inventory_tests;

/// Admit a fixture's own archive scan, without borrowing another fixture's process-global registry.
#[cfg(test)]
pub(crate) fn fixture(
    process: &ProcessResources,
    plugins: &busbar_kernel::config::PluginsCfg,
) -> Result<FileImages, String> {
    let mut linked: Vec<_> = busbar_kernel::preflight::linked_rows()
        .iter()
        .map(super::linked_row)
        .collect();
    linked.extend(super::linked_exports(crate::LINKED.export_doors)?);
    let metadata = super::scanned_registry(linked, plugins)?;
    let policy = super::trust_policy(plugins, env!("CARGO_PKG_VERSION"))?;
    let mut admitted = Vec::new();
    for row in crate::LINKED.images {
        admitted.push((
            (row.admit)().map_err(|error| error.to_string())?,
            row.alias.to_owned(),
        ));
    }
    for row in metadata.loadable().iter().filter(|row| !row.linked()) {
        if let Ok(image) =
            busbar_plugin_loader::admit::admit_bytes(&row.lib_bytes, &row.manifest, &policy)
        {
            admitted.push((image, row.manifest.alias.clone()));
        }
    }
    let proofs: BTreeMap<String, ImageProof> = admitted
        .iter()
        .map(|(image, _)| {
            (
                image.identity().to_owned(),
                ImageProof {
                    kind: image.kind(),
                    digest: image.sha256().copied(),
                },
            )
        })
        .collect();
    let aliases: Vec<(String, String)> = admitted
        .iter()
        .map(|(image, alias)| (image.identity().to_owned(), alias.clone()))
        .collect();
    let mut builder = ImagesBuilder::new(&HOST, Arc::clone(process.slots()), Ceilings::DEFAULT);
    for (image, _) in admitted {
        builder.admit(image).map_err(|error| error.to_string())?;
    }
    let images = builder.finish();
    let grammar = crate::root::secret_grammar::of_images(
        &images,
        super::owners_of(&metadata),
        super::classify(&metadata, Some(plugins)),
        super::skip_lines(metadata.skipped()),
    )?;
    let grammar = with_http_instances(grammar, &aliases, &proofs, &images)?;
    Ok(FileImages {
        images,
        aliases,
        grammar,
        proofs,
    })
}

/// The process's one set of plugin resources (a process installs its plugin sinks once): made by the start stage,
/// before the start grammar, and reused by the boot.
pub(crate) fn process() -> Result<Arc<ProcessResources>, String> {
    static PROCESS: std::sync::OnceLock<Result<Arc<ProcessResources>, String>> =
        std::sync::OnceLock::new();
    PROCESS
        .get_or_init(|| ProcessResources::new().map(Arc::new))
        .clone()
}

/// The start stage's native image prepare (WP3 step 2): the configured `plugins:` block's images verified,
/// read and described (no instance opens), and their secret grammar published as the native secret axis, before
/// the start scan and the start grammar. So `--validate`, `--list-plugins` and the start grammar read the native
/// secret words, from the one source every later read uses. With no readable `plugins:` block the linked images
/// alone are prepared.
pub(crate) fn publish_start() -> Result<(), String> {
    let process = process()?;
    let plugins = super::configured_block().unwrap_or_else(|| busbar_kernel::config::PluginsCfg {
        enabled: false,
        ..Default::default()
    });
    let prepared = prepare(&process, &PhaseOneIn::of(&plugins)).map_err(|refusal| refusal.0)?;
    prepared.publish_secrets();
    prepared.publish_hooks();
    Ok(())
}

/// The recognizer's plane instance names, and which of them serve HTTP routes on the data
/// listener: oauth_as protects exactly those planes' audiences (WP1-GAP r3, section 2.3).
fn with_http_instances(
    grammar: Grammar,
    aliases: &[(String, String)],
    proofs: &BTreeMap<String, ImageProof>,
    images: &Images,
) -> Result<Grammar, String> {
    let sections = busbar_plugin_loader::instance::plane_sections::plane_sections(
        aliases
            .iter()
            .filter(|(identity, _)| {
                proofs
                    .get(identity)
                    .is_some_and(|proof| proof.kind == busbar_plugin_abi::types::KindCode::Plane)
            })
            .map(|(identity, alias)| (identity.as_str(), alias.as_str())),
        busbar_kernel::config::recognizer::is_core_key,
    )
    .map_err(|refusal| refusal.to_string())?;
    let serving = sections
        .names()
        .filter(|name| {
            sections
                .identity_of_section(name)
                .is_some_and(|identity| images.serves_http(identity))
        })
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let by_identity: BTreeMap<String, String> = sections
        .names()
        .filter_map(|name| {
            sections
                .identity_of_section(name)
                .map(|identity| (identity.to_owned(), name.to_owned()))
        })
        .collect();
    let grammar = name_sections(grammar, &by_identity, |identity| {
        proofs.get(identity).and_then(|proof| proof.digest)
    });
    Ok(grammar.with_http_instances(serving))
}

/// The recognizer's strict-parse Section items are the planes' instance names. A plane the
/// running registry recorded keeps the instance name it was bound under, even when its archive is
/// gone; an admitted plane is renamed to the loader's instance name, and listed when the start
/// judgement did not list it (a read before start registered its planes).
pub(crate) fn name_sections(
    mut grammar: Grammar,
    by_identity: &BTreeMap<String, String>,
    digest_of: impl Fn(&str) -> Option<[u8; 32]>,
) -> Grammar {
    use busbar_kernel::config::grammar::{Item, ItemKind, Standing};
    for item in &mut grammar.items {
        if item.kind == ItemKind::Section {
            if let Some(name) = by_identity.get(&item.module) {
                item.name.clone_from(name);
            }
        }
    }
    for (identity, name) in by_identity {
        if grammar
            .items
            .iter()
            .any(|item| item.kind == ItemKind::Section && &item.name == name)
        {
            continue;
        }
        let image = digest_of(identity).map_or_else(
            || "linked".to_owned(),
            |digest| digest.iter().map(|byte| format!("{byte:02x}")).collect(),
        );
        grammar.items.push(Item {
            kind: ItemKind::Section,
            name: name.clone(),
            module: identity.clone(),
            image,
            standing: Standing::Counts,
        });
    }
    grammar
}
