//! DECISIONS #40: the two raw secret-byte accessors are sealed behind
//! `busbar_contract::plugin::KernelSeal`. A plugin has no symbol to reach the bytes (proven by the
//! `compile_fail` doctests on `SecretValue::expose` and `KeyMaterial::bytes`); this file proves the
//! kernel side — a seal-holder — still resolves the material and that the seal names its origin for
//! the access journal (the audit the design requires).

use busbar_contract::plugin::KernelSeal;
use busbar_contract::{KeyMaterial, SecretValue};

/// Stands in for a kernel-side capability token. Only a crate holding such a seal can read raw
/// secret bytes; the `seal_origin` is what the access journal records.
struct KernelResolver;
impl KernelSeal for KernelResolver {
    fn seal_origin(&self) -> &'static str {
        "busbar-contract::tests::secret_accessor_seal"
    }
}

#[test]
fn kernel_seal_holder_resolves_the_secret_bytes() {
    let seal = KernelResolver;
    let secret = SecretValue::new(b"resolved-token".to_vec());
    // The kernel path still resolves through the seal.
    assert_eq!(secret.expose(&seal), b"resolved-token");
}

#[test]
fn kernel_seal_holder_reads_key_material() {
    let seal = KernelResolver;
    let key = KeyMaterial::new(b"signing-key".to_vec(), 1_700_000_000);
    assert_eq!(key.bytes(&seal), b"signing-key");
    assert_eq!(key.fetched_at, 1_700_000_000);
}

#[test]
fn the_seal_names_its_origin_for_the_access_journal() {
    // The audit entry the resolution writes is keyed by the seal's origin; without a seal there is
    // no read, so every read is attributable.
    let seal = KernelResolver;
    assert_eq!(
        seal.seal_origin(),
        "busbar-contract::tests::secret_accessor_seal"
    );
}
