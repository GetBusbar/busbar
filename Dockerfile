# busbar container image: FROM scratch, because the binary is the whole product.
# Static musl binaries are built in CI (see .github/workflows/docker.yml) and copied
# in per-arch; CA roots are compiled into the binary (webpki-roots), so no /etc/ssl
# is needed. The vetted provider catalog ships inside the image as the default.
#
# The first-party `busbar-headroom` hook plugin (local BM25 prompt-compression rewrite gate; see
# https://github.com/GetBusbar/headroom-hook) ships PRE-INSTALLED: its signed tarball is baked in
# at /etc/busbar/plugins, and the image's default config.yaml (docker/config.yaml, copied to
# /etc/busbar/config.yaml) enables plugins and wires headroom into the default pool — so
# compression works with zero plugin setup. Mounting your own config.yaml (see below) replaces
# that default entirely; copy its `plugins:`/`hooks:` blocks into yours to keep headroom wired.
# `busbar-webrequest` (the other first-party hook plugin) is NOT pre-installed: it forwards to an
# operator-chosen URL, so it has no zero-config default — see docs/plugins.md.
#
# /lib/lib{c.musl-*,gcc_s,stdc++}.* below are NOT busbar's own runtime deps (the busbar binary
# itself is fully static) — they are what the headroom plugin cdylib needs at dlopen() time.
# aarch64-unknown-linux-musl's Rust target does not support `cdylib` output under Rust's default
# (crt-static-on) linking, so headroom-hook's cdylib is built with crt-static explicitly disabled
# (see docker.yml), which makes it a normally-dynamically-linked musl/C++ shared object instead of
# the usual self-contained static-pie one. Bundling its exact runtime libs (built in the same
# musl-native container, so the ABI matches) is what makes dlopen() succeed in a FROM-scratch image
# that otherwise has no libc at all — verified end to end with a real `--validate` run.
#
# Run (zero-config quickstart — headroom active, one provider):
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
COPY plugins/${TARGETARCH}/busbar-headroom.tar.gz /etc/busbar/plugins/busbar-headroom.tar.gz
COPY plugins/${TARGETARCH}/lib/ /lib/

ENV BUSBAR_PROVIDERS=/etc/busbar/providers.yaml \
    BUSBAR_CONFIG=/etc/busbar/config.yaml

EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/busbar"]
