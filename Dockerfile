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
# Governance (optional) needs a writable volume for the SQLite file, e.g.
#   -v busbar-data:/var/lib/busbar   with governance.db_path: /var/lib/busbar/governance.db
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
