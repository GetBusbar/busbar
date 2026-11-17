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
    let admitted = crate::root::min3_boot::admit_images(&plugins).map_err(GrammarRefusal)?;
    let proofs = admitted
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
    let proofs = admitted
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
    let aliases = admitted
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
    Ok(FileImages {
        images,
        aliases,
        grammar,
        proofs,
    })
}
