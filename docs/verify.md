# Verifying a busbar release

Every busbar release can be checked without trusting GitHub, Docker Hub, our CI, or this website.
Each check below names the key it relies on and what it proves.

**What protects you, and what doesn't.** These signatures protect you only if you check them. If you
pull `latest` or download a binary without verifying it, you are trusting the registries. The
installer (`install.sh`) runs the binary check below for you.

## The keys

| Key | Signs | Where it lives | Where you get it |
|---|---|---|---|
| **Release key** `busbar-release-2026a`, plus backup `-2026b` | `SHA256SUMS`, `SHA256SUMS.plugins`, `IMAGES`, `release-evidence.json` (OpenSSH signatures, namespace `busbar-release`) | A FIDO2 hardware key the founder holds; it needs a physical touch. The backup is in a safe | [`release/allowed_signers`](../release/allowed_signers), `https://getbusbar.com/keys/allowed_signers`, and SECURITY.md. All three must match |
| **Plugin keys** `busbar-plugins-2026a` (signing) and `-2026b` (sealed next key) | Every first-party plugin's manifest (Ed25519) | The founder's hardware key (PIV) | **Compiled into the busbar binary** (`BUSBAR_RELEASE_PUBKEY` in [`.cargo/config.toml`](../.cargo/config.toml), embedded verbatim, so `strings busbar \| grep busbar-plugins-` shows it) |

**One key, two namespaces, never interchangeable.** The release key signs release *files* only
under the OpenSSH signature namespace `busbar-release`. Every line of `allowed_signers` is limited to
that namespace (`namespaces="busbar-release"`), and the publish gate refuses any other line. Release
*statements* arrive with our CI's next phase. The same hardware key signs them under the separate
namespace `busbar-release-statement`, and they are verified against a list restricted to that
namespace. A file signature can therefore never be replayed as a statement, nor a statement as a file
signature.

No key that signs a busbar release or a first-party plugin is held by any CI system, GitHub secret
or cloud account. A stolen forge token, CI token or registry token cannot produce any of these
signatures.

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

**At load.** Busbar verifies every first-party plugin when it loads it, against the plugin keys
compiled into the binary. A plugin that is unsigned, tampered with, or signed by any other key is
refused, and the refusal names the reason. Nothing is configured for this, and turning on
`plugins.trust.allow_unsigned` is the only way to load an unsigned plugin.

**Offline, before you install:**

```sh
# The plugin release lists its signed tarballs in SHA256SUMS(.sig), signed by the release key:
ssh-keygen -Y verify -f allowed_signers -I busbar-release -n busbar-release -s SHA256SUMS.sig < SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
# and the manifest signature, with the same code the loader runs:
busbar-plugin-pack verify busbar-store-sqlite-1.6.0-x86_64-unknown-linux-gnu.tar.gz \
  --keys "$(sed -n 's/^BUSBAR_RELEASE_PUBKEY = "\(.*\)"/\1/p' .cargo/config.toml)" \
  --name busbar-store-sqlite --version 1.6.0
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
artifacts/       busbar-<target>.<archive> per published target in .github/release-targets.json; busbar-openapi-v<V>.json
plugins/         <repo>-<version>-<target>.tar.gz, UNSIGNED, per plugins.yaml entry and plugin target
sboms/           busbar-v<V>-<target>.cdx.json per published target and image platform
internal/        busbar-<musl target>.tar.gz (the binaries inside the image)
oci/             busbar.oci.tar (OCI layout of the multi-platform image)
SHA256SUMS       every file in artifacts/ and sboms/
IMAGES           busbar sha256:<image index digest>
```
