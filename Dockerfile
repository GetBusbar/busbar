# busbar container image.
#
# ── WHY THIS IS NOT `FROM scratch` ANY MORE ─────────────────────────────────────────────────────
# It was, over a static musl binary, and the result was an image in which NO PLUGIN OF ANY KIND
# COULD LOAD. A busbar plugin is a cdylib and loading one is a `dlopen`; the image's binary was an
# `ELF ... static-pie linked` with no `PT_INTERP` at all, and musl's STATIC libc provides `dlopen`
# only as a stub that always refuses. The operator's symptom was
#
#     [warn] memfd load unavailable for plugin '...' (... dlopen failed); falling back to private
#            temp staging
#     [error] store 'sqlite' plugin load failed: cannot create private plugin staging dir
#            /tmp/busbar-plugins-...: No such file or directory
#
# and the missing `/tmp` was a RED HERRING. Given a writable `/tmp` the same image said `dlopen
# failed` instead; and the same binary, lifted OUT of the container onto a full glibc host with a
# real `/tmp`, an absolute `plugins.dir`, and every `NEEDED` library of the plugin resolvable by
# `ldd`, STILL said `dlopen failed`. The base was never the whole defect: the BINARY'S LINKAGE was.
# Two things therefore had to change together, and neither alone is sufficient:
#
#   1. the binary is built for `*-unknown-linux-gnu` and is DYNAMICALLY linked, so it has a real
#      `ld.so` and a real `dlopen` (see .github/workflows/docker.yml's build-binaries job); and
#   2. the base supplies that `ld.so` plus glibc, `libm`, `libgcc_s` — which is exactly what every
#      published first-party plugin asks for:
#        NEEDED libgcc_s.so.1 / libm.so.6 / libc.so.6 / ld-linux-x86-64.so.2
#      Every plugin GetBusbar publishes is a `*-unknown-linux-gnu` asset (there is no musl asset for
#      any of them — see testing/shadow-oracle/plugin-digests.tsv), so a musl image could not have
#      loaded them even with a dynamic musl binary. glibc is not a preference here, it is the ABI
#      the published plugins were compiled against.
#
# THE BASE. `debian:bookworm-slim`, PINNED BY DIGEST. `gcr.io/distroless/cc-debian12:nonroot` was
# measured beside it and is genuinely smaller (9.2 MB vs 28.2 MB of base) and already non-root, but
# it lives on `gcr.io` — a registry this project does not otherwise depend on — and adding a
# registry to the supply chain to save 19 MB is the wrong trade. bookworm-slim is on the registry
# busbar already publishes to and already pulls its CI service images from. The digest below is the
# pin; the floating tag beside it is a comment for humans, exactly like every `uses:` in CI.
#
# THE SAME IMAGE SERVES EVERY PLUGIN KIND. A store plugin and a hook plugin are both a `dlopen` of a
# verified image; there is no store-specific runtime here and there must never be one.
#
# ── WHAT AN OPERATOR NEEDS, IN FULL ─────────────────────────────────────────────────────────────
# Ships with ZERO plugins pre-installed — same treatment every first-party plugin gets, store, auth,
# and hook alike. A plugin is a plugin: none of them are baked into this image or into busbar's own
# release. Want a specific plugin pre-wired (e.g. Headroom's prompt compression)? See that plugin's
# OWN repo — some ship their own bundled "busbar + plugin, one image" convenience variant (e.g.
# https://github.com/GetBusbar/headroom-hook publishes `getbusbar/busbar-headroom`). This image is
# the plain core: drop a signed plugin tarball into `/etc/busbar/plugins` yourself.
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
# Run (a durable SQLite governance store — the four keys, the volume, the tarball; see
# docs/deployment.md's "busbar in Docker, with a plugin" recipe for the whole thing):
#   docker run -d -p 8080:8080 \
#     -e BUSBAR_ADMIN_TOKEN \
#     -v busbar-plugins:/etc/busbar/plugins:ro \   # the signed tarball lives here
#     -v busbar-data:/var/lib/busbar \             # the database outlives the container here
#     -v "$PWD/config.yaml:/etc/busbar/config.yaml:ro" \
#     getbusbar/busbar
# with config.yaml carrying ALL FOUR of:
#   plugins.enabled: true
#   plugins.dir: /etc/busbar/plugins     # ABSOLUTE. A relative dir resolves against the process's
#                                        # working directory and the tarball is simply not found.
#   store.module: sqlite                 # the tarball's manifest `alias` (or its `name`)
#   store.settings.db_path: /var/lib/busbar/governance.db   # ON THE VOLUME, or it dies with it
#
# Pre-flight, before any of that:
#   docker run --rm -v ...same mounts... getbusbar/busbar --list-plugins --probe-load
# `--probe-load` actually `dlopen`s each verified tarball IN THIS IMAGE and prints `LOADS` only if
# it really mapped. A bare `--list-plugins` checks signatures and says `VERIFIED (not loaded)`,
# because that is all it did — the 1.5.5 image printed `LOADS` for a tarball it could not load, and
# an operator surface that answers a question it never asked is a defect whichever way it guesses.

# debian:bookworm-slim — the pin is the digest; the tag is a comment for humans.
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS base

ARG TARGETARCH
COPY binaries/${TARGETARCH}/busbar /busbar

# THE IMAGE REFUSES TO BUILD OVER A BINARY THAT CANNOT dlopen. This is the gate that would have
# stopped 1.5.5: a `static-pie` musl binary names no interpreter and links no `libc.so.6`, so `ldd`
# prints `statically linked` and this RUN fails the build with the reason in as many words. It costs
# one layer in a stage that is thrown away and it makes "plugins load in this image" a build-time
# property rather than something discovered by an operator three months after the release.
RUN set -eu; \
    out="$(ldd /busbar 2>&1 || true)"; \
    echo "$out"; \
    case "$out" in \
      *libc.so.6*) : ;; \
      *) echo "REFUSING TO BUILD: /busbar is not dynamically linked against glibc." >&2; \
         echo "A busbar plugin is a cdylib and loading one is a dlopen; a static binary's musl" >&2; \
         echo "dlopen is a stub that always fails, so this image could load NO plugin of any" >&2; \
         echo "kind. Build the image binary for *-unknown-linux-gnu." >&2; \
         exit 1 ;; \
    esac

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

# The busbar runtime user. 65532:65532 is the same uid the FROM-scratch image ran as, so an operator
# whose host volume is already owned by 65532 needs to change nothing. Created as a real passwd/group
# entry rather than left as a bare numeric USER: glibc's NSS answers `getpwuid()` for it, which is
# what keeps a library that resolves the current user from failing inside the container.
RUN set -eu; \
    groupadd --system --gid 65532 busbar; \
    useradd --system --uid 65532 --gid 65532 --home-dir /var/lib/busbar --shell /usr/sbin/nologin busbar; \
    # THE DURABLE-STORE MOUNT, owned by the runtime user. Left to the default, a host directory
    # bind-mounted here is readable and NOT writable by uid 65532, and sqlite's open() then fails
    # with a message about the DATABASE rather than about the mount — the confusing shape this
    # ownership exists to keep out of an operator's day. (A named volume inherits this ownership;
    # a bind mount carries the host's, which is why the docs say to chown it.)
    install -d -o 65532 -g 65532 -m 0755 /var/lib/busbar; \
    # WHERE A PLUGIN TARBALL GOES. Present and empty in the image so the documented `-v ...:ro`
    # mount lands on a path that exists, and so `--list-plugins` over a plugin-less image says
    # "no plugin tarballs found" rather than an error about a missing directory.
    install -d -o 65532 -g 65532 -m 0755 /etc/busbar/plugins; \
    # THE LOADER'S STAGING FALLBACK. On Linux the verified bytes go to an anonymous `memfd` and
    # touch no filesystem, but that path needs a mounted /proc, and when it is unavailable the
    # loader stages into `<temp>/busbar-plugins-<pid>-<rnd>` at 0700. debian ships /tmp at 1777 and
    # this line asserts it rather than assuming it: a base that ever stopped shipping /tmp would
    # otherwise reproduce 1.5.5's exact "cannot create private plugin staging dir" boot refusal.
    test -d /tmp && test -w /tmp || { echo "no writable /tmp for the plugin staging fallback" >&2; exit 1; }

COPY --from=base /busbar /busbar
COPY providers.yaml /etc/busbar/providers.yaml
COPY docker/config.yaml /etc/busbar/config.yaml

ENV BUSBAR_PROVIDERS=/etc/busbar/providers.yaml \
    BUSBAR_CONFIG=/etc/busbar/config.yaml

# Declared so `docker run` without `-v` still gives the governance store a writable, non-layer
# home — an operator who forgets the volume loses the data on `docker rm`, but never boots into a
# read-only overlay and a refusal that reads like a busbar bug.
VOLUME ["/var/lib/busbar"]

EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/busbar"]
