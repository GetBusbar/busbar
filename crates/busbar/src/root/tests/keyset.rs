// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The deployment keyset (spec #82(a); ARCHITECTURE.md §1.2, PB-13; architect ruling 2026-09-26):
//! ephemeral without a data directory, minted-and-cached with one, and the one `KeysetMissing`
//! refusal in its exact words.

use super::*;
use crate::root::durability::{build_priced, keyset_of, DurabilityConfig, KeySetVerifier};
use busbar_kernel_ledger::legacy::RecordingRows;
use busbar_kernel_wal::NullShipper;

const NOW: u64 = 1_700_000_000;

fn token() -> Grant<DurableWrite> {
    crate::root::kernel::new_kernel().durability_token()
}

fn node(data_dir: Option<&Path>) -> Durability {
    build_priced(
        &DurabilityConfig {
            data_dir: data_dir.map(Path::to_path_buf),
        },
        0,
        Box::new(NullShipper::new()),
        Box::new(RecordingRows::new()),
        Box::new(|| None),
    )
    .expect("the book opens")
}

/// A data directory that removes itself.
struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "busbar-keyset-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("a clock after the epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("the fixture directory is creatable");
        Dir(path)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Boot a node over `dir` and bind its keyset, as the boot does.
fn boot(dir: &Path) -> (Durability, Result<KeysetSource, KeysetError>) {
    let mut durability = node(Some(dir));
    let bound = bind(&mut durability, Some(dir), &token(), StepName::Meter, NOW);
    (durability, bound)
}

/// A fixed checkpoint seal, signed by the chain when it has a key.
fn seal(durability: &mut Durability) -> busbar_kernel_ledger::checkpoint::Checkpoint {
    durability
        .seal_checkpoint(&token(), StepName::Meter, NOW + 1)
        .expect("the node seals")
}

/// AN EPHEMERAL NODE VERIFIES ITS OWN BOOT'S SIGNATURES (PB-13): no data directory, a key minted
/// for this process, the chain and the checkpoints signed with it, and the node's own keyset
/// verifies both. RED arm: a second ephemeral boot mints a DIFFERENT key, and the first boot's seal
/// does not verify against it — nothing survives the process, which is what ephemeral means.
#[test]
fn an_ephemeral_node_verifies_its_own_boots_signatures() {
    let mut first = node(None);
    assert!(
        first.record.signing_key_id().is_none(),
        "a book is built keyless"
    );
    assert_eq!(
        bind_ephemeral(&mut first).expect("an ephemeral keyset mints"),
        KeysetSource::Ephemeral
    );
    let key_id = first
        .record
        .signing_key_id()
        .expect("the chain now signs")
        .to_string();
    let checkpoint = seal(&mut first);
    assert!(checkpoint.signature.is_some(), "the checkpoint is signed");
    checkpoint
        .verify_seal(&KeySetVerifier::new(keyset_of(&first.record)))
        .expect("the node's own keyset verifies its own boot's seal");

    let mut second = node(None);
    bind_ephemeral(&mut second).expect("an ephemeral keyset mints");
    assert_ne!(
        second.record.signing_key_id(),
        Some(key_id.as_str()),
        "every ephemeral boot mints its own key"
    );
    assert_eq!(
        checkpoint
            .verify_seal(&KeySetVerifier::new(keyset_of(&second.record)))
            .expect_err("another boot's keyset cannot vouch for this seal")
            .to_string(),
        "checkpoint 1's signature does not verify against the keyset: the signature does not \
         verify against this key"
    );
}

/// FIRST BOOT WITH A DATA DIRECTORY: the keyset is minted, cached under the directory at 0600, and
/// its fingerprint sealed by a `Bootstrap` record on the journal — the first record on the chain.
#[test]
fn the_first_boot_with_a_data_dir_mints_caches_0600_and_seals_a_bootstrap() {
    let dir = Dir::new("mint");
    let (durability, bound) = boot(&dir.0);
    let file = dir.0.join(KEYSET_FILE);
    assert_eq!(
        bound.expect("the first boot mints"),
        KeysetSource::Minted { file: file.clone() }
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&file)
            .expect("the keyset file is written")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the keyset file is 0600");
    }
    let records = durability
        .journal
        .replay()
        .expect("reads back")
        .expect("verifies");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].class, RecordClass::Bootstrap);
    let cached = AuditSigningKey::from_hex_seed(
        &std::fs::read_to_string(&file).expect("the keyset file reads"),
    )
    .expect("the file holds a seed");
    assert_eq!(
        bootstrap_fingerprint(&records[0].body),
        Some(fingerprint_of_signer(&cached)),
        "the Bootstrap seals the cached key's fingerprint"
    );
    assert_eq!(
        durability.record.signing_key_id(),
        Some(cached.key_id()),
        "the chain signs with the cached key"
    );
}

/// A RESTART with the directory intact reads the cache and signs with the SAME key, sealing no
/// second `Bootstrap`.
#[test]
fn a_restart_with_the_data_dir_signs_with_the_same_key() {
    let dir = Dir::new("restart");
    let (first, bound) = boot(&dir.0);
    bound.expect("the first boot mints");
    let key_id = first.record.signing_key_id().map(str::to_string);
    drop(first);

    let (second, bound) = boot(&dir.0);
    assert_eq!(
        bound.expect("the restart reads the cache"),
        KeysetSource::Cached {
            file: dir.0.join(KEYSET_FILE)
        }
    );
    assert_eq!(second.record.signing_key_id().map(str::to_string), key_id);
    let bootstraps = second
        .journal
        .replay()
        .expect("reads back")
        .expect("verifies")
        .iter()
        .filter(|r| r.class == RecordClass::Bootstrap)
        .count();
    assert_eq!(bootstraps, 1, "one deployment, one Bootstrap");
}

/// THE REFUSAL, in its exact words: `data_dir` set, a `Bootstrap` on the chain, and the keyset file
/// gone — neither the file nor the store yields the fingerprint.
#[test]
fn keyset_missing_refuses_in_its_exact_words_when_the_file_is_gone() {
    let dir = Dir::new("missing");
    let (first, bound) = boot(&dir.0);
    bound.expect("the first boot mints");
    let fingerprint = sealed_fingerprint(&first).expect("the Bootstrap is sealed");
    drop(first);
    std::fs::remove_file(dir.0.join(KEYSET_FILE)).expect("the keyset file is removed");

    let (second, bound) = boot(&dir.0);
    let refused = bound.expect_err("a bootstrapped deployment with no keyset refuses");
    assert_eq!(
        refused.to_string(),
        format!(
            "KeysetMissing: the journal under {dir} holds a Bootstrap sealing keyset fingerprint \
             {fp}, and neither the keyset file {dir}/deployment-keyset nor the configured store \
             yields that fingerprint. Restore this node's data_dir (the keyset file beside its \
             journal), or boot against a store that holds the deployment keyset",
            dir = dir.0.display(),
            fp = hex::encode(fingerprint),
        )
    );
    assert!(
        second.record.signing_key_id().is_none(),
        "a refused node signs nothing"
    );
    assert!(
        !dir.0.join(KEYSET_FILE).exists(),
        "the refusal never mints a replacement"
    );
}

/// The file yields a DIFFERENT key than the one the `Bootstrap` sealed: the same refusal.
#[test]
fn keyset_missing_refuses_a_file_holding_another_key() {
    let dir = Dir::new("other");
    let (first, bound) = boot(&dir.0);
    bound.expect("the first boot mints");
    drop(first);
    std::fs::write(dir.0.join(KEYSET_FILE), format!("{}\n", "11".repeat(32)))
        .expect("the file is replaced");
    let (_, bound) = boot(&dir.0);
    assert!(
        matches!(bound, Err(KeysetError::Missing(_))),
        "another key is not the deployment keyset: {bound:?}"
    );
}

/// No `Bootstrap` and no data directory: never `KeysetMissing` (PB-13), however many boots.
#[test]
fn no_data_dir_never_refuses_and_writes_nothing() {
    for _ in 0..2 {
        let mut durability = node(None);
        assert_eq!(
            bind(&mut durability, None, &token(), StepName::Meter, NOW),
            Ok(KeysetSource::Ephemeral)
        );
        assert_eq!(
            durability.journal.next_seq(),
            1,
            "an ephemeral keyset seals no Bootstrap: nothing depends on it"
        );
    }
}

/// A cache file with no `Bootstrap` on the chain (the journal started over) is ADOPTED and sealed,
/// never replaced: keys are only ever added.
#[test]
fn a_cached_keyset_with_no_bootstrap_is_adopted_not_replaced() {
    let dir = Dir::new("adopt");
    let seed = "22".repeat(32);
    std::fs::write(dir.0.join(KEYSET_FILE), format!("{seed}\n")).expect("the file is planted");
    let expected = AuditSigningKey::from_hex_seed(&seed).expect("a seed");
    let (durability, bound) = boot(&dir.0);
    bound.expect("the cached keyset is adopted");
    assert_eq!(durability.record.signing_key_id(), Some(expected.key_id()));
    assert_eq!(
        sealed_fingerprint(&durability),
        Some(fingerprint_of_signer(&expected))
    );
}
