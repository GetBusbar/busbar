# busbar container image: FROM scratch, because the binary is the whole product.
# Static musl binaries are built in CI (see .github/workflows/docker.yml) and copied
# in per-arch; CA roots are compiled into the binary (webpki-roots), so no /etc/ssl
# is needed. The vetted provider catalog ships inside the image as the default.
#
# Ships with ZERO plugins pre-installed — same treatment every first-party plugin gets, store, auth,
# and hook alike. A plugin is a plugin: none of them are baked into this image or into busbar's own
# release. Want a specific plugin pre-wired (e.g. Headroom's prompt compression)? See that plugin's
# OWN repo — some ship their own bundled "busbar + plugin, one image" convenience variant for users
# who came specifically for that plugin and just want it running (e.g.
# https://github.com/GetBusbar/headroom-hook publishes `getbusbar/busbar-headroom`). This image is
# the plain core: drop a signed plugin tarball into `/etc/busbar/plugins` yourself (see
# docs/plugins.md) if you want one.
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
# image sets no WORKDIR); (3) store.module: sqlite + store.settings.db_path on a writable volume
# (its directory must already exist); (4) the signed tarball actually IN plugins.dir — either
# bind-mount it yourself, or let Busbar fetch it via
# `plugins.fetch: [{ github: "GetBusbar/store-sqlite@vX" }]` (resolves to
# https://github.com/GetBusbar/store-sqlite/releases/download/vX/store-sqlite.tar.gz), in which
# case plugins.dir must itself be WRITABLE (the fetch downloads into it). Example:
#   -v busbar-plugins:/etc/busbar/plugins -v busbar-data:/var/lib/busbar
# See docs/getting-started.md#durable-store-giving-persistence-a-writable-volume for the full
# walkthrough (including the exact refusal text for each way this goes wrong) and
# docker/docker-compose.yml for a wired-up example.
FROM scratch

ARG TARGETARCH
COPY binaries/${TARGETARCH}/busbar /busbar
COPY providers.yaml /etc/busbar/providers.yaml
COPY docker/config.yaml /etc/busbar/config.yaml

ENV BUSBAR_PROVIDERS=/etc/busbar/providers.yaml \
    BUSBAR_CONFIG=/etc/busbar/config.yaml

EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/busbar"]
