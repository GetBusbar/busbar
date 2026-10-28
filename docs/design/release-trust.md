# Release trust for first-party plugins (busbar 1.6.0)

Status: **provisional wire format** (`spec_version` `0.1-provisional`). The chain, the checks and
the refusals below are what busbar 1.6.0's loader enforces. The byte encoding is meant to match
ModernCI's release-signing "v1 formats" before 1.6.0 ships, and it lives in one module
(`crates/plugin-loader/src/release_trust/wire.rs`) so that it can change without touching the chain.

Code: `crates/plugin-loader/src/release_trust/` (the chain and the encoding),
`crates/plugin-loader/src/sign.rs` (`first_party_signer`, `evaluate`), `crates/plugin-loader/src/pack.rs`
(the release tooling), `scripts/release/publish_gate.py` (the release gate). Tests:
`crates/plugin-loader/src/tests/release_trust_tests.rs` and `release_seal_tests.rs`.

## 1. The chain

```
ROOT keys (compiled into busbar: BUSBAR_RELEASE_PUBKEY)
  └─ sign ─> KEYS DOCUMENT       role "busbar-plugins": signer key ids + threshold,
                                 expires, version (only rises), revocations
                └─ names ─> RELEASE SIGNER(s)
                              └─ sign ─> RELEASE MANIFEST   every artefact of one release:
                                                            name, version, target, sha256
                                           └─ lists ─> ARTEFACT  a plugin's canonical manifest bytes,
                                                                 which pin its library by sha256
```

- **Root.** Busbar ships ROOT public keys only. A root signs keys documents, nothing else.
  `ROOT_THRESHOLD` is 1: any one root vouches. 1.6.0's roots are `busbar-plugins-root` (ECDSA
  P-256, Cloud KMS, HSM protection level, non-exportable) and `busbar-plugins-2026a` (ECDSA P-256,
  PIV slot 9C of the owner's YubiKey 5Ci, PIN and touch on every signature). The YubiKey's firmware
  (5.4.3) has no PIV Ed25519, so roots are P-256.
- **Keys document** (TUF's root metadata, with its delegation to a targets role). It names the
  signer keys of each product role, with a threshold. First-party plugins are the role
  `busbar-plugins`. It carries an `expires` and a `version`. It also carries signed revocations of
  signer keys and of artefact digests. A new release signer, a retired signer and a revocation are
  each a new keys document that a root signs. None of them needs a new busbar binary.
- **Release manifest** (TUF's targets metadata). One per release, signed once. It lists every
  artefact of the release for every target.
- **Artefact.** A plugin's canonical manifest bytes (`sign::canonical_manifest_bytes`: every
  manifest field except `signature`, as sorted-key JSON). They include `sha256`, the library's
  digest, so the listed hash binds the manifest and the library together.

A plugin carries its **seal**, which is the keys document and the release manifest, in its
manifest's `signature` field. That field is outside the canonical bytes, so sealing never changes
what the release lists. A sealed tarball is still `manifest.json` plus the library, and the tarball
format is unchanged.

### 1.6.0 key roles

| Key | Algorithm | Held | Signs |
|---|---|---|---|
| `busbar-plugins-root` | ECDSA P-256 | Cloud KMS, HSM, non-exportable; no IAM grants beyond the owner | keys documents |
| `busbar-plugins-2026a` | ECDSA P-256 | YubiKey PIV 9C (generated later; not needed to ship) | keys documents (and it may also be named as a release signer) |
| interim release signer | ECDSA P-256 | ModernCI's secret store; generated fresh for this purpose (never the old `BUSBAR_SIGN_KEY`) | release manifests, in CI, only after every check is green |
| ModernCI release signer (later) | per ModernCI v1 | ModernCI's feature | release manifests; it replaces the interim signer through a new keys document |

The interim signer's keys document expires **90 days** after it is signed, so the signer must be
vouched for again or replaced.

## 2. What the loader checks, in order

Each check is one refusal. The **code** goes into the audit record (the `PLUGIN_SKIPPED_TRUST_POLICY`
diagnostic carries the reason, and the reason names the code). The **message** says what failed and
what to do.

| # | Check | Refusal code | Opt-in may admit? |
|---|---|---|---|
| 1 | The seal and both documents parse as one well-formed document of their kind | `release-seal-malformed` | `allow_unsigned` only |
| 2 | At least `ROOT_THRESHOLD` distinct compiled-in roots signed the keys document | `keys-signature` | `allow_unsigned` only |
| 3 | The keys document has not expired (`expires` > now) | `keys-expired` | `allow_unsigned` only |
| 4 | Its version is not below the highest one this deployment has accepted | `keys-rollback` | **never** (AntiDowngrade) |
| 5 | It names a `busbar-plugins` role with at least one key id and a threshold of 1 or more | `keys-no-role` | `allow_unsigned` only |
| 6 | The release manifest names that role, and at least `threshold` distinct, non-revoked keys of the role signed it | `release-signature`, or `signer-revoked` when only revoked signers signed | `release-signature`: `allow_unsigned` only. `signer-revoked`: **never** (Revoked) |
| 7 | The release manifest has not expired | `release-expired` | `allow_unsigned` only |
| 8 | Neither the artefact digest nor the library digest is revoked by the keys document | `digest-revoked` | **never** (Revoked) |
| 9 | The release manifest lists the plugin's name and version | `not-in-release` | `allow_unsigned` only |
| 10 | It lists them for this binary's target (`PLUGIN_TARGET`, its Rust target triple) | `wrong-target` | `allow_unsigned` only |
| 11 | The listed sha256 equals the sha256 of the plugin's canonical manifest bytes | `hash-mismatch` | `allow_unsigned` only |

Before any of these checks, the library's sha256 must equal the manifest's `sha256`, as for every
plugin. Nothing here defaults open. An empty role, a zero threshold, an unknown field, an unknown
`spec_version` or an unknown algorithm is a refusal. `allow_unsigned` is the operator's existing
explicit opt-in for plugins that cannot prove trust. A seal that fails a check is handled exactly
like any other failed first-party signature, and loading under the opt-in still emits
`PLUGIN_LOADED_UNVERIFIED`. Revocation and rollback are hard rejects that no opt-in relaxes, just
like the compiled-in revocation list and the anti-downgrade floors.

**Rollback floor.** The highest accepted keys-document version is stored beside the per-plugin
anti-downgrade marks in the data dir's marks file, under the reserved mark `busbar-release-keys`
(`<version>.0.0`). The registry build loads it into `TrustPolicy::release_keys_floor`. Every
verified, sealed first-party plugin raises it. Without a data dir, the floor is held in memory
only, as the plugin marks are.

**Release manifest rollback.** Busbar does not track a floor for release manifests. TUF uses its
snapshot role for that. Busbar instead relies on the per-plugin anti-downgrade marks, which already
refuse an older version of a plugin this deployment has loaded. A release manifest's `version` is
the signing time in Unix seconds, so it rises anyway.

**Timestamp role.** Busbar has none. The loader works offline from what the tarball carries, so it
has no fresh timestamp to fetch. The keys document's expiry is the bound on freeze attacks.

## 3. The wire format (provisional; `release_trust/wire.rs`)

The format is modelled on TUF, and the places where it differs are named.

**Canonical JSON.** Object keys are sorted bytewise, with no whitespace. Numbers are non-negative
integers only. Strings use printable ASCII only (0x20 to 0x7E), and only `"` and `\` are escaped.
Anything outside this subset is refused. For the subset, this is byte-identical to OLPC canonical
JSON (TUF's) and to Python's `json.dumps(v, sort_keys=True, separators=(",", ":"))`.

**Envelope** (TUF's):

```json
{"signatures":[{"keyid":"<hex>","sig":"<hex>"}],"signed":{ ... }}
```

The signature covers the canonical bytes of `signed`. The verifier re-canonicalizes `signed` and
never trusts the envelope's own spacing.

**Key object** (TUF's), and **key id** = lowercase hex SHA-256 of the key object's canonical bytes:

```json
{"keytype":"ecdsa","keyval":{"public":"04<128 hex>"},"scheme":"ecdsa-sha2-nistp256"}
{"keytype":"ed25519","keyval":{"public":"<64 hex>"},"scheme":"ed25519"}
```

Deviation from TUF: TUF writes an ECDSA public key as PEM. This format uses the hex of the 65-byte
uncompressed SEC1 point, which keeps the verifier free of a PEM parser.

**Signatures.**

- ECDSA P-256 (`ecdsa-sha2-nistp256`): ASN.1 DER `SEQUENCE { r, s }` over SHA-256 of the signed
  bytes, in hex. That is what Cloud KMS (`ec-sign-p256-sha256`), a YubiKey PIV slot and
  `openssl dgst -sha256 -sign` all emit, and what TUF uses. DER is used rather than fixed
  `r || s`, so no signer's output is re-encoded. A high-S signature is accepted.
- Ed25519: the 64 raw bytes, in hex, verified strictly.

Busbar verifies P-256 with `ring` (`ECDSA_P256_SHA256_ASN1`), the build's one crypto backend.

**Times.** `YYYY-MM-DDTHH:MM:SSZ`, UTC.

**Keys document** (`_type` `busbar-keys`):

```json
{"signed":{
  "_type":"busbar-keys","spec_version":"0.1-provisional","version":1,"expires":"2027-01-26T00:00:00Z",
  "keys":{"<keyid>":<key object>},
  "roles":{"busbar-plugins":{"keyids":["<keyid>"],"threshold":1}},
  "revocations":{"keyids":["<keyid>"],"digests":{"<sha256>":"<why>"}}},
 "signatures":[{"keyid":"<root keyid>","sig":"<hex DER>"}]}
```

**Release manifest** (`_type` `targets`):

```json
{"signed":{
  "_type":"targets","spec_version":"0.1-provisional","version":1793204252,"expires":"2027-01-26T00:00:00Z",
  "role":"busbar-plugins",
  "targets":{"<name>/<version>/<target>":{"length":1234,"hashes":{"sha256":"<hex>"},
                                          "custom":{"name":"…","version":"…","target":"…"}}}},
 "signatures":[{"keyid":"<signer keyid>","sig":"<hex DER>"}]}
```

The target path must equal `<name>/<version>/<target>` of its `custom`. `length` and
`hashes.sha256` describe the canonical manifest bytes.

**Seal** (in the plugin manifest's `signature` field): `seal:` followed by the canonical JSON
`{"keys":<keys envelope>,"targets":<release manifest envelope>}`. A per-plugin Ed25519 signature
(128 hex digits, the pre-1.6.0 shape) never starts with `seal:`, so the two are distinct.

**Root key list** (`BUSBAR_RELEASE_PUBKEY`): comma-separated `<id>:p256:<130 hex>`, with
`<id>:ed25519:<64 hex>`, `<id>:<64 hex>` and a bare `<64 hex>` (a run key) also accepted. The id
names the root in refusals. Signatures find a root by key id.

### What may change to match ModernCI v1

The following are all in `wire.rs`, and the chain in `release_trust/mod.rs` does not depend on them:

- the canonicalization;
- the envelope (TUF's, DSSE, or another);
- the key object and key id rule;
- the algorithm tags;
- the signature encodings, including the offline encoding of a WebAuthn assertion;
- the document `_type` names;
- the seal's spelling.

The decoded shapes (`KeysDoc`, `TargetsDoc`, `ReleaseKey`) and the checks in section 2 are the
contract.

## 4. Release flow

1. ModernCI's candidate checks build every plugin **unsigned** (`busbar-plugin-pack pack`). Nothing
   is rebuilt after that.
2. Once every check is green, the signing step runs:
   - `busbar-plugin-pack release-manifest --version <unix time> --expires <keys doc expiry> --out rm.signed <tarball>=<target>...`
     writes the signed bytes of the one release manifest.
   - The release signer signs `rm.signed` **once**: `CMD rm.signed rm.sig`.
     - `scripts/release/sign-key-env.sh` is the interim CI signer. It reads the PEM from the step's
       secret environment through a pipe and never writes it to disk.
     - `sign-kms.sh` signs with Cloud KMS.
     - `sign-piv.sh` signs with PIV 9C.
   - `busbar-plugin-pack envelope --signed rm.signed --key p256:<signer> --signature rm.sig --out release-manifest.json`
     refuses a signature that does not verify.
   - For each tarball, `busbar-plugin-pack seal <tarball> --keys-doc keys.json --release release-manifest.json --target <t> --keys <root list> --out signed/<tarball>`.
     It refuses unless the result verifies through the whole chain for its target.
   - `busbar-plugin-pack verify` runs again on the written bytes.
3. The owner's gate (`publish_gate.py sign` / `plugin-release`) runs the same sequence through
   `seal_release`, with `--k1-sign-cmd` as the signer command. Its trust file names the root list
   (`k1`), the release signer (`release_signer`) and the current keys document (`keys_doc`).

A keys document is made with `busbar-plugin-pack keys-doc --spec spec.json --out keys.signed`. The
spec has these fields: `version`, `expires`, `signers` (as `["p256:<hex>"]`), `threshold`,
`revoked_keyids` and `revoked_digests`. A root signs `keys.signed` (`sign-kms.sh keys.signed
keys.sig`), and `busbar-plugin-pack envelope --key <root> ...` wraps the signature.

## 5. Open questions

1. **Expiry and installed plugins.** The loader checks expiry against the current time on every
   boot. A sealed dropped-in plugin therefore stops loading when its keys document (90 days) or its
   release manifest expires, unless it is replaced by a re-sealed copy. A config that names the
   plugin then fails at boot. Linked (compiled-in) plugins are unaffected. Three ways out:
   - judge expiry at install or fetch time instead of at every boot;
   - let the operator drop a newer keys document beside the plugins;
   - use a longer expiry for the keys documents that releases ship with.

   The owner needs to rule on this before 1.6.0.
2. **Root count.** `the_default_release_key_input_is_the_real_release_key_list` requires at least
   two committed keys. With only the KMS root committed, it stays red until the PIV root exists.
3. **ModernCI requirement 1** ("ModernCI never holds a private key that can sign a release on its
   own") does not hold for the interim signer, which the owner ruled is held in ModernCI's secret
   store until the feature ships.
