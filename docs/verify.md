# Verifying a busbar release

Every busbar release can be checked without trusting GitHub, Docker Hub, our CI, or this website.
Each check below names the key it relies on and what it proves.

**What protects you, and what doesn't.** These signatures protect you only if you check them. If you
pull `latest` or download a binary without verifying it, you are trusting the registries. The
installer (`install.sh`) runs the binary check below for you.

## The keys

| Key | Signs | Where it lives | Where you get it |
|---|---|---|---|
| **Release key** `busbar-release-2026a`, plus backup `-2026b` | `SHA256SUMS`, `SHA256SUMS.plugins`, `IMAGES`, `release-evidence.json` (OpenSSH signatures, namespace `busbar-release`), and the version tag `v<V>` (namespace `git`) | A FIDO2 hardware key the founder holds; it needs a physical touch. The backup is in a safe | [`release/allowed_signers`](../release/allowed_signers), `https://getbusbar.com/keys/allowed_signers`, and SECURITY.md. All three must match |
| **Plugin root keys** `busbar-plugins-root` and `busbar-plugins-2026a` (ECDSA P-256) | Plugin **keys documents** only: each names the current plugin release signer, with an expiry and a version that only rises, and carries signed revocations | `busbar-plugins-root`: Cloud KMS at the HSM protection level, non-exportable. `busbar-plugins-2026a`: PIV slot 9C of the founder's YubiKey (PIN and touch on every signature) | **Compiled into the busbar binary** (`BUSBAR_RELEASE_PUBKEY` in [`.cargo/config.toml`](../.cargo/config.toml), embedded verbatim, so `strings busbar \| grep busbar-plugins-` shows it) |
| **Plugin release signer** (named by the current keys document) | One **release manifest** per release, listing every first-party plugin artefact (name, version, target, SHA-256) | 1.6.0: an interim P-256 key in our CI's secret store, vouched for by a keys document that expires after 90 days. It is replaced by our CI's release-signing feature through a new keys document, with no new busbar binary | Inside every plugin tarball, in the keys document a root signed ([design](design/release-trust.md)) |

**One key, separate namespaces, never interchangeable.** The release key signs release *files* only
under the OpenSSH signature namespace `busbar-release`, and the version tag only under `git` (the
namespace git uses for SSH-signed tags). Every line of `allowed_signers` is limited to exactly one of
the two (`namespaces="busbar-release"` or `namespaces="git"`), each `git` line names the same release
key, and the publish gate refuses any other line. Release
*statements* arrive with our CI's next phase. The same hardware key signs them under the separate
namespace `busbar-release-statement`, and they are verified against a list restricted to that
namespace. A file signature can therefore never be replayed as a statement, nor a statement as a file
signature.

No key that signs a busbar release file is held by any CI system, GitHub secret or cloud account.
The plugin root keys are held in an HSM and on a hardware key; neither can be exported. The interim
plugin release signer is held by our CI's secret store and signs only after every check is green; a
stolen copy is bounded by its keys document's 90-day expiry and is revoked by the next keys document
a root signs, with no new busbar binary.

The keys above take effect with 1.6.0. Releases up to 1.5.5 trust an older plugin key,
`b18395a3…`, which was held as a CI secret. 1.6.0 does not trust it. Upgrade rather than keep a 1.5.x
binary that does.

## A binary

```sh
V=1.6.0
base=https://github.com/GetBusbar/busbar/releases/download/v$V
curl -fsSLO "$base/SHA256SUMS" -fsSLO "$base/SHA256SUMS.sig" -fsSLO "$base/busbar-x86_64-unknown-linux-gnu.tar.gz"
curl -fsSL https://getbusbar.com/keys/allowed_signers -o allowed_signers   # compare with release/allowed_signers
ssh-keygen -Y verify -f allowed_signers -I busbar-release -n busbar-release -s SHA256SUMS.sig < SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing          # macOS: shasum -a 256 -c SHA256SUMS --ignore-missing
```

`ssh-keygen` comes with OpenSSH 8.2 or later, which macOS, Linux and Windows already ship. A
"Good signature" line, followed by `OK` for your file, means two things:
- the founder's hardware key signed this list of digests;
- your download matches the list.

Each release has a CycloneDX SBOM per target, `busbar-v<V>-<target>.cdx.json`, listed in the same
`SHA256SUMS`.

## The version tag

Each release is cut under an annotated version tag that the release key signed. The publish gate
refuses to publish unless `v<V>` is such a tag, verifies against `allowed_signers`, and names the
release commit, and the GitHub Release is created on that same tag object.

```sh
git fetch origin tag v$V
git -c gpg.ssh.allowedSignersFile="$PWD/allowed_signers" verify-tag v$V
# Good "git" signature for busbar-release with ED25519-SK key SHA256:...
```

Releases up to 1.5.5 were tagged without a signature.

## The release index

`busbar --migrate-config` reads `plugin-index.json` to rewrite a 1.5.5 configuration's
`plugins.fetch` pins and to find the release of a plugin built for this core. Each release publishes
it as an asset of its own GitHub Release, the URL the binary fetches by default:

```
https://github.com/GetBusbar/busbar/releases/download/v<V>/plugin-index.json
```

It is listed in that release's `SHA256SUMS`, so the release key's signature covers it:
`sha256sum -c SHA256SUMS --ignore-missing` checks it like any binary. To read an index from
somewhere else (a mirror, an offline copy, a path), set `BUSBAR_PLUGIN_INDEX` to its path or
`https` URL.

## A container image

```sh
curl -fsSLO "$base/IMAGES" -fsSLO "$base/IMAGES.sig"
ssh-keygen -Y verify -f allowed_signers -I busbar-release -n busbar-release -s IMAGES.sig < IMAGES
cat IMAGES                                        # busbar sha256:<index digest>
docker pull getbusbar/busbar@sha256:<index digest>   # or ghcr.io/getbusbar/busbar@sha256:…
```

Always deploy **by digest**, in compose and in Helm (`image.digest`). A tag can be moved by whoever
controls the registry. A digest the release key signed cannot be.

**cosign.** Each image index also carries a cosign signature, and that signature is in the public
Rekor log. The signing identity is printed in each release's notes and in `release-evidence.json`. For example:

```sh
cosign verify --certificate-identity release@getbusbar.com \
  --certificate-oidc-issuer https://accounts.google.com ghcr.io/getbusbar/busbar@sha256:<index digest>
```

**Kubernetes admission** (sigstore policy-controller):

```yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata: { name: busbar-release }
spec:
  images: [{ glob: "ghcr.io/getbusbar/busbar**" }, { glob: "index.docker.io/getbusbar/busbar**" }]
  authorities:
    - keyless:
        identities: [{ issuer: https://accounts.google.com, subject: release@getbusbar.com }]
```

## A plugin

**At load.** Busbar verifies every first-party plugin when it loads it, through its chain: the
plugin's keys document must be signed by a root key compiled into the binary, unexpired, and no
older than one this deployment has accepted; the release manifest must be signed by the release
signer that keys document names, and must list the plugin, for this binary's target, under its exact
SHA-256. A plugin that is unsigned, tampered with, unlisted, built for another target, revoked, or
signed by any other key is refused, and the refusal names the reason and its audit code
([design](design/release-trust.md)). Nothing is configured for this, and turning on
`plugins.trust.allow_unsigned` is the only way to load an unsigned plugin.

**Offline, before you install:**

```sh
# The plugin release lists its signed tarballs in SHA256SUMS(.sig), signed by the release key:
ssh-keygen -Y verify -f allowed_signers -I busbar-release -n busbar-release -s SHA256SUMS.sig < SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
# and the plugin's chain (root -> keys document -> release manifest -> plugin), with the same code
# the loader runs:
busbar-plugin-pack verify busbar-store-sqlite-1.6.0-x86_64-unknown-linux-gnu.tar.gz \
  --keys "$(sed -n 's/^BUSBAR_RELEASE_PUBKEY = "\(.*\)"/\1/p' .cargo/config.toml)" \
  --target x86_64-unknown-linux-gnu --name busbar-store-sqlite --version 1.6.0
```

`busbar-plugin-pack` is built from this repository:

```sh
cargo build --release -p busbar-plugin-loader --features pack --bin busbar-plugin-pack
```

## The transparency log

Every release-key signature and every image signature is recorded in the public
[Rekor](https://search.sigstore.dev) log. Search by the sha256 of `SHA256SUMS` or by the image
digest. If you find a busbar release that has no log entry, or a log entry signed by our key with no
matching release, tell security@getbusbar.com. Either one means something is wrong. We watch the log
for our keys too.

## What a release does not prove yet

Each item below is a gap, stated plainly; nothing on this site claims it.
- **No SLSA provenance for 1.6.0.** Our build service does not produce it yet. When it does, this
  page will give the `slsa-verifier` command.
- **Reproducibility is not proven.** A second, independent builder rebuilds each release, and the
  comparison is in `release-evidence.json` (`reproducible`). Until it matches for every target,
  nothing claims "reproducible".
- **No founder release statement yet.** It is a signed statement over the version, commit and every
  digest, checked by the build service before anything is published, and it arrives with our CI's
  next phase. Today the founder's signature covers the files above, and our own release tooling
  refuses to publish without it.
- **Outbound TLS revocation is not checked.** busbar's TLS client (rustls) does not check OCSP.

## For builders: the candidate layout

Our CI writes this layout for the owner's publish run. The gate, `scripts/release/publish_gate.py`,
documents every rule it applies:

```
candidate.json   {"version","commit","repo","test_kit":{"tag","commit"},"plugins":[{"repo","version","tag","commit"}]}
artifacts/       busbar-<target>.<archive> per published target in .github/release-targets.json; busbar-openapi-v<V>.json;
                 plugin-index.json (rendered from candidate.json's plugins and their tarballs' manifests)
plugins/         <repo>-<version>-<target>.tar.gz, UNSIGNED, per plugins.yaml entry and plugin target
sboms/           busbar-v<V>-<target>.cdx.json per published target and image platform
internal/        busbar-<musl target>.tar.gz (the binaries inside the image)
oci/             busbar.oci.tar (OCI layout of the multi-platform image)
SHA256SUMS       every file in artifacts/ and sboms/
IMAGES           busbar sha256:<image index digest>
```
