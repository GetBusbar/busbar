# busbar container image: the SAME linux-gnu binary as the release tarball, on a minimal glibc base.
#
# W17, THE LINKING DESIGN. Every plugin works compiled-in OR dropped-in, and a dropped-in plugin is
# opened with dlopen (crates/plugin-loader). A fully static musl binary cannot dlopen at all: musl's
# static libc answers every dlopen with "Dynamic loading not supported". So this image no longer
# carries a static musl build on a scratch base (which could load no dropped-in plugin, whatever was
# put in /lib). It packages the published busbar-<arch>-unknown-linux-gnu binary, byte for byte
# (`image_matches_packaged_binary` in .github/artifact-contract.json), built on the glibc 2.28
# baseline with every Rust/C dependency (TLS, crypto, jemalloc) linked in, so all it needs from the
# image is glibc, its loader and libgcc_s. The image and the tarball are one artifact, and a plugin
# built for linux-gnu loads in both (`image_dropin_loads` proves it on every release).
#
# The base is gcr.io/distroless/cc-debian12:nonroot: glibc, libgcc_s, CA roots, tzdata and
# /etc/passwd with uid 65532, and nothing else: no shell, no package manager (docker:no-shell). It is
# pinned by its multi-arch INDEX digest so amd64 and arm64 resolve from one pin; dependabot
# (docker ecosystem) proposes digest bumps. CA roots are also compiled into the binary
# (webpki-roots), so the image's own are not relied on. The vetted provider catalog ships inside the
# image as the default.
#
# Ships with ZERO plugins pre-installed — same treatment every first-party plugin gets, store, auth,
# and hook alike. A plugin is a plugin: none of them are baked into this image or into busbar's own
# release. Want a specific plugin pre-wired? See that plugin's OWN repo — a plugin may ship its own
# bundled "busbar + plugin, one image" convenience variant. This image is the plain core: drop a
# signed plugin tarball into `/etc/busbar/plugins` yourself (see docs/plugins.md) if you want one.
#
# Run (one provider, no plugins):
#   docker run -d -p 8080:8080 \
#     -e ANTHROPIC_KEY -e BUSBAR_ADMIN_TOKEN \
#     getbusbar/busbar
#
# Run (your own config — see config.yaml at the repo root for the full annotated walkthrough):
#   docker run -d -p 8080:8080 \
#     -e ANTHROPIC_KEY \
#     -v "$PWD/config.yaml:/etc/busbar/config.yaml:ro" \
#     getbusbar/busbar
#
# Governance (optional) is a signed plugin, not code baked into this image — "a writable volume"
# is necessary but not sufficient. The complete recipe is four things: (1) plugins.enabled: true
# (default false = a hard boot refusal if store.module names a plugin); (2) an ABSOLUTE
# plugins.dir (the default, "plugins", is relative and resolves to /plugins here, since this
# image sets WORKDIR /); (3) store.module: sqlite + store.settings.db_path on a writable volume
# (its directory must already exist); (4) the signed tarball actually IN plugins.dir — either
# bind-mount it yourself, or let Busbar fetch it via
# `plugins.fetch: [{ github: "GetBusbar/busbar-store-sqlite@vX" }]` (resolves to
# https://github.com/GetBusbar/busbar-store-sqlite/releases/download/vX/store-sqlite.tar.gz), in which
# case plugins.dir must itself be WRITABLE (the fetch downloads into it). Example:
#   -v busbar-plugins:/etc/busbar/plugins -v busbar-data:/var/lib/busbar
# See docs/getting-started.md#durable-store-giving-persistence-a-writable-volume for the full
# walkthrough (including the exact refusal text for each way this goes wrong) and
# docker/docker-compose.yml for a wired-up example.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

ARG TARGETARCH
COPY binaries/${TARGETARCH}/busbar /busbar
COPY providers.yaml /etc/busbar/providers.yaml
COPY docker/config.yaml /etc/busbar/config.yaml

# The distroless base sets WORKDIR /home/nonroot. Reset it to / so every relative path in a config
# (the default `plugins.dir: plugins` above all) resolves exactly as it did on the scratch image:
# /plugins, as documented in the header.
WORKDIR /

ENV BUSBAR_PROVIDERS=/etc/busbar/providers.yaml \
    BUSBAR_CONFIG=/etc/busbar/config.yaml

EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/busbar"]
