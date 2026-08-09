#!/usr/bin/env python3
"""verify-artifact - ONE verifier, run once per shipped artifact, checking EVERY contract row.

WHAT THIS EXISTS FOR.

busbar 1.5.3 shipped four unix binaries. Three embedded the plugin release public key and one --
busbar-aarch64-unknown-linux-gnu -- did not, so on ARM Linux every correctly-signed first-party
plugin was refused. It was not a 1.5.3 regression: 1.5.1 and 1.5.2 shipped the same broken leg. It
was one matrix leg that never had the property, unexercised until somebody ran a signed plugin on a
Graviton box.

Three structural faults let that happen, and this file exists to close the second and third:

  1. TWO BUILD PATHS PRODUCED ONE RELEASE. Closed in .github/workflows/build-artifact.yml: one
     reusable workflow, one build step, one env block, every target native.
  2. EVERY PROPERTY WAS ASSERTED ON THE INPUT, NEVER ON THE OUTPUT. Setting an env var on a build
     step says the key was INTENDED to be embedded. `option_env!` is a compile-time read that fails
     silently to `None`, so only reading the shipped bytes says whether it WAS. Every row below is
     an assertion about an artifact that was downloaded from the release, never about the build
     that made it.
  3. THE PRODUCED SET AND THE VERIFIED SET WERE NEVER COMPARED. Closed in release.yml, whose
     `verify-artifact` matrix is enumerated from the SAME `targets` job that produced the build
     matrix, and whose `verify-set-equality` job fails if the two sets differ in either direction.

THE ROWS ARE DATA, IN .github/artifact-contract.json, AND THIS FILE IMPLEMENTS THEM.

Adding a property is one row there plus one function here. It then applies to every target
automatically -- there is no per-target list a platform can be forgotten from, which is exactly how
the aarch64 leg went three releases without a key. `_assert_contract_is_whole` enforces SET EQUALITY
between the declared ids and the implemented checks in BOTH directions: a row with no
implementation is a hard failure rather than a silently-skipped property, and an implementation
with no row is a check nobody can see.

THERE IS NO SKIP, NO WAIVER AND NO EXCEPTION LIST. A row either applies to a target (via the row's
`applies_when`, matched against that target's own declaration in .github/release-targets.json) or it
does not. `--rows` restricts a run to named rows for local diagnosis: it reports the verdict PARTIAL and
exits 2, never 0, so a partial run can never be mistaken for a green one and cannot be wired into
CI as a pass.

Usage:
    scripts/verify-artifact.py --archive busbar-aarch64-unknown-linux-gnu.tar.gz \\
        --target aarch64-unknown-linux-gnu --version 1.5.4 --pubkey <64 hex> \\
        --evidence ./evidence --plugin ./busbar-store-sqlite-1.0.4-....tar.gz \\
        --repo GetBusbar/busbar --repo-root .

Exit codes: 0 every applicable row passed | 1 at least one row failed | 2 PARTIAL (--rows).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_TARGETS = os.path.join(ROOT, ".github", "release-targets.json")
DEFAULT_CONTRACT = os.path.join(ROOT, ".github", "artifact-contract.json")

# Below any real busbar archive by a wide margin and far above a header-only or empty upload.
MIN_ARCHIVE_BYTES = 1024 * 1024


class RowFailure(Exception):
    """A contract row was not satisfied. The message is the operator-facing explanation."""


# =================================================================================================
# BINARY HEADER PARSING
#
# Parsed out of the ELF / Mach-O / PE headers directly rather than shelling out to `file`, `ldd`,
# `otool` or `dumpbin`. One implementation that behaves identically on all three runner operating
# systems, and -- the part that matters for this contract -- it reads the artifact's OWN bytes, so
# the aarch64 asset is checked for aarch64 content even when the checking runner is x86_64. A tool
# that only executes the binary can never notice an asset carrying the wrong architecture.
# =================================================================================================

_ELF_MACHINE = {0x3E: "x86_64", 0xB7: "aarch64"}
_MACHO_CPU = {0x01000007: "x86_64", 0x0100000C: "aarch64"}
_PE_MACHINE = {0x8664: "x86_64", 0xAA64: "aarch64"}


def _read_elf(data: bytes):
    """(arch, linkage) for a 64-bit little-endian ELF."""
    if data[4] != 2 or data[5] != 1:
        raise RowFailure("ELF is not 64-bit little-endian (ei_class=%d ei_data=%d)" % (data[4], data[5]))
    (machine,) = struct.unpack_from("<H", data, 18)
    arch = _ELF_MACHINE.get(machine, "unknown(e_machine=0x%x)" % machine)
    (phoff,) = struct.unpack_from("<Q", data, 32)
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    # PT_INTERP (3) names the dynamic loader. Its ABSENCE is what "statically linked" means on ELF,
    # and its presence in a musl FROM-scratch image binary is the failure docker.yml hard-fails on.
    interp = any(
        struct.unpack_from("<I", data, phoff + i * phentsize)[0] == 3 for i in range(phnum)
    )
    return arch, ("dynamic" if interp else "static")


def _read_macho(data: bytes):
    """(arch, linkage) for a 64-bit Mach-O. Fat/universal binaries are refused on purpose."""
    (magic,) = struct.unpack_from("<I", data, 0)
    if magic in (0xCAFEBABE, 0xBEBAFECA):
        raise RowFailure(
            "the binary is a FAT/universal Mach-O. busbar ships one single-architecture binary per "
            "target so the asset name and the bytes agree; a fat binary makes the aarch64 asset and "
            "the x86_64 asset indistinguishable, which is the confusion this row exists to prevent."
        )
    if magic != 0xFEEDFACF:
        raise RowFailure("not a 64-bit Mach-O (magic=0x%08x)" % magic)
    (cputype,) = struct.unpack_from("<i", data, 4)
    arch = _MACHO_CPU.get(cputype & 0xFFFFFFFF, "unknown(cputype=0x%x)" % (cputype & 0xFFFFFFFF))
    (ncmds,) = struct.unpack_from("<I", data, 16)
    off, dylib = 32, False
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmdsize == 0:
            break
        if cmd == 0x0C:  # LC_LOAD_DYLIB
            dylib = True
            break
        off += cmdsize
    return arch, ("dynamic" if dylib else "static")


def _read_pe(data: bytes):
    """(arch, linkage) for a PE/COFF image."""
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise RowFailure("MZ header present but no PE signature at e_lfanew=0x%x" % e_lfanew)
    (machine,) = struct.unpack_from("<H", data, e_lfanew + 4)
    arch = _PE_MACHINE.get(machine, "unknown(machine=0x%x)" % machine)
    opt = e_lfanew + 24
    (opt_magic,) = struct.unpack_from("<H", data, opt)
    # Data directories start after the optional header's fixed part: 112 bytes for PE32+ (0x20b),
    # 96 for PE32. Entry 1 is the import table; a linked-against-nothing image has RVA 0.
    dd = opt + (112 if opt_magic == 0x20B else 96)
    (import_rva,) = struct.unpack_from("<I", data, dd + 8)
    return arch, ("dynamic" if import_rva else "static")


def read_binary_identity(path: str):
    """(format, arch, linkage) of an executable, from its own header bytes."""
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:4] == b"\x7fELF":
        return ("elf",) + _read_elf(data)
    if data[:2] == b"MZ":
        return ("pe",) + _read_pe(data)
    if len(data) >= 4 and struct.unpack_from("<I", data, 0)[0] in (
        0xFEEDFACF, 0xCAFEBABE, 0xBEBAFECA
    ):
        return ("macho",) + _read_macho(data)
    raise RowFailure("unrecognised object format (first 4 bytes: %r)" % data[:4])


# =================================================================================================
# HELPERS
# =================================================================================================


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_archive(archive: str, dest: str) -> list:
    """Unpack `archive` into `dest` and return its member names, refusing traversal entries."""
    if archive.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            names = [n for n in zf.namelist() if not n.endswith("/")]
            _refuse_traversal(names)
            zf.extractall(dest)
    else:
        with tarfile.open(archive, "r:*") as tf:
            members = [m for m in tf.getmembers() if m.isfile()]
            names = [m.name for m in members]
            _refuse_traversal(names)
            tf.extractall(dest, members=members)
    return sorted(names)


def _refuse_traversal(names: list) -> None:
    for n in names:
        if n.startswith("/") or ".." in n.replace("\\", "/").split("/"):
            raise RowFailure("archive member escapes the extraction directory: %r" % n)


def run(cmd: list, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def http_body(url: str, timeout: float = 5.0) -> str:
    with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310 - fixed localhost URL
        return r.read().decode("utf-8", "replace").strip()


# =================================================================================================
# THE CONTRACT ROWS
#
# One function per row id in .github/artifact-contract.json. Each raises RowFailure with an
# operator-facing explanation, or returns a one-line note on success. `_assert_contract_is_whole`
# proves the two sets are identical, so this docstring cannot drift from the data file.
# =================================================================================================


def row_archive_shape(ctx) -> str:
    size = os.path.getsize(ctx.archive)
    if size < MIN_ARCHIVE_BYTES:
        raise RowFailure(
            "the archive is %d bytes, under the %d-byte floor. GitHub lists an asset row the moment "
            "an upload starts, so a truncated upload is indistinguishable from a good one by name "
            "alone." % (size, MIN_ARCHIVE_BYTES)
        )
    want = [ctx.spec["exe"]]
    if ctx.members != want:
        raise RowFailure(
            "the archive contains %r; the contract says exactly %r. The documented install is "
            "`tar -xzf ... && ./%s`, and install.sh copies that one name: any other shape is a "
            "broken install on this platform." % (ctx.members, want, ctx.spec["exe"])
        )
    if not os.path.exists(ctx.exe):
        raise RowFailure("member %r did not materialise at %s" % (ctx.spec["exe"], ctx.exe))
    return "%d bytes, members %r" % (size, ctx.members)


def row_binary_format(ctx) -> str:
    fmt, arch, linkage = read_binary_identity(ctx.exe)
    want = (ctx.spec["format"], ctx.spec["arch"], ctx.spec["linkage"])
    got = (fmt, arch, linkage)
    if got != want:
        raise RowFailure(
            "the shipped binary is (format=%s arch=%s linkage=%s) but %s declares "
            "(format=%s arch=%s linkage=%s). An asset whose bytes do not match its name is 100%% "
            "broken for everyone who downloads it, and executing it on the runner that built it "
            "cannot notice." % (got + (ctx.target,) + want)
        )
    return "format=%s arch=%s linkage=%s" % got


def row_release_pubkey(ctx) -> str:
    key = ctx.pubkey
    if not re.fullmatch(r"[0-9a-fA-F]{64}", key or ""):
        raise RowFailure(
            "no usable BUSBAR_RELEASE_PUBKEY was supplied to the verifier (got %r). The verifier "
            "refuses to search for nothing and call it a pass: an empty needle is found in every "
            "binary." % key
        )
    with open(ctx.exe, "rb") as fh:
        blob = fh.read()
    if key.lower().encode() not in blob.lower():
        raise RowFailure(
            "the 64-hex release public key is NOT present in the shipped binary. "
            "`option_env!(\"BUSBAR_RELEASE_PUBKEY\")` is read at COMPILE time and fails silently to "
            "`None`, so the build was green and the comment claimed the key was baked in while this "
            "artifact carried none. This is exactly the busbar-aarch64-unknown-linux-gnu defect that "
            "shipped in 1.5.1, 1.5.2 and 1.5.3: on this platform every correctly-signed first-party "
            "plugin is refused and the only workaround is plugins.trust.allow_unsigned, which "
            "disables the requirement instead of trusting first-party. FIX: the build step must "
            "carry BUSBAR_RELEASE_PUBKEY; scripts/release-build.sh refuses to build without it."
        )
    return "key %s… present" % key[:12]


def row_first_party_plugin(ctx) -> str:
    probe = ctx.targets["plugin_probe"]
    if not ctx.plugin or not os.path.exists(ctx.plugin):
        raise RowFailure(
            "the signed first-party plugin tarball (%s %s, asset %s) was not provided to the "
            "verifier, so the functional half of the key check could not run. A row that cannot run "
            "is RED, never skipped: this is the row that would have caught the aarch64 defect."
            % (probe["repo"], probe["tag"], ctx.spec["plugin_asset"])
        )
    work = os.path.join(ctx.work, "plugin-probe")
    plugins = os.path.join(work, "plugins")
    os.makedirs(plugins, exist_ok=True)
    shutil.copy2(ctx.plugin, os.path.join(plugins, os.path.basename(ctx.plugin)))
    providers = os.path.join(work, "providers.yaml")
    config = os.path.join(work, "config.yaml")
    with open(providers, "w") as fh:
        fh.write('mock:\n  protocol: openai\n  base_url: "http://127.0.0.1:9"\n  api_key_env: MOCK_KEY\n')
    with open(config, "w") as fh:
        fh.write(
            'listen: "127.0.0.1:0"\n'
            "providers_file: %s\n"
            "providers:\n  mock:\n    api_key: { env: MOCK_KEY }\n"
            "models:\n  m:\n    provider: mock\n"
            "plugins:\n  enabled: true\n  dir: %s\n" % (json.dumps(providers), json.dumps(plugins))
        )
    env = dict(os.environ, BUSBAR_CONFIG=config, BUSBAR_PROVIDERS=providers, MOCK_KEY="x")
    proc = run([ctx.exe, "--list-plugins"], env=env)
    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        raise RowFailure("`busbar --list-plugins` exited %d:\n%s" % (proc.returncode, out))
    # --list-plugins falls back to the DEFAULT plugins block with a mere [warn] when the config is
    # unreadable, and then honestly reports an empty inventory. Without these two assertions the row
    # would read "no plugin tarballs found", find no failure text, and go green having verified
    # nothing at all -- a check that passes without executing.
    if "plugins.enabled: true" not in out:
        raise RowFailure(
            "the binary did not read the probe config (no `plugins.enabled: true` in the output); it "
            "fell back to the default plugins block, so this row inspected NOTHING:\n%s" % out
        )
    if "no plugin tarballs found" in out:
        raise RowFailure("the binary found no plugin tarball in the probe directory:\n%s" % out)
    rows = [ln for ln in out.splitlines() if os.path.basename(ctx.plugin) in ln and "FILE" not in ln]
    if len(rows) != 1:
        raise RowFailure("expected exactly 1 inventory row for the probe plugin, got %d:\n%s" % (len(rows), out))
    line = rows[0].rstrip()
    want_sig, want_status = probe["expect_signature"], probe["expect_status"]
    if not re.search(r"\b%s\b" % re.escape(want_sig), line) or not line.endswith(want_status):
        raise RowFailure(
            "the shipped binary does NOT accept a genuinely signed first-party plugin. Expected "
            "SIGNATURE `%s` and STATUS `%s`; got:\n  %s\n"
            "This is the functional form of the 1.5.3 aarch64 defect -- against that artifact this "
            "row reports `SIGNATURE: unsigned` and `SKIPPED: manifest claims first-party publisher "
            "'busbar' but this build embeds no busbar release key`. The plugin is a real signed "
            "release of %s %s, so a failure here means this binary's embedded key is missing or is "
            "not the public half of the key the plugin repos sign with."
            % (want_sig, want_status, line, probe["repo"], probe["tag"])
        )
    return "%s %s verifies as %s/%s" % (probe["repo"], probe["tag"], want_sig, want_status)


def row_version_anchored(ctx) -> str:
    proc = run([ctx.exe, "--version"])
    if proc.returncode != 0:
        raise RowFailure("`busbar --version` exited %d:\n%s%s" % (proc.returncode, proc.stdout, proc.stderr))
    got = (proc.stdout or "").strip()
    want = re.compile(r"busbar %s" % re.escape(ctx.version))
    if not want.fullmatch(got):
        raise RowFailure(
            "`busbar --version` printed %r; the release is %s. The match is ANCHORED on both ends on "
            "purpose: a prefix match lets `%s` be satisfied by `%s0`, and a substring match lets a "
            "stale binary from another leg pass while claiming to be this release."
            % (got, ctx.version, ctx.version, ctx.version)
        )
    return got


def row_quickstart_boots(ctx) -> str:
    work = os.path.join(ctx.work, "quickstart")
    os.makedirs(work, exist_ok=True)
    # The exact minimal config from docs/getting-started.md Step 2. `listen` is OMITTED so the
    # documented default (0.0.0.0:8080) is itself part of what this proves.
    with open(os.path.join(work, "config.yaml"), "w") as fh:
        fh.write(
            "providers:\n  anthropic:\n    api_key: { env: ANTHROPIC_KEY }\n"
            "models:\n  claude-sonnet:\n    provider: anthropic\n"
        )
    src = os.path.join(ctx.repo_root, "providers.yaml")
    if not os.path.exists(src):
        raise RowFailure(
            "providers.yaml is not present at %s. The documented quickstart needs it beside the "
            "binary (install.sh fetches it), so without it this row cannot run -- and a row that "
            "cannot run is RED." % src
        )
    shutil.copy2(src, os.path.join(work, "providers.yaml"))
    env = dict(
        os.environ,
        BUSBAR_CONFIG=os.path.join(work, "config.yaml"),
        BUSBAR_PROVIDERS=os.path.join(work, "providers.yaml"),
        # Syntactically valid and deliberately fake: this row asserts BOOT and /healthz, which are
        # provider-independent, and must never spend a real provider call.
        ANTHROPIC_KEY="sk-ant-verify-artifact-dummy",
    )
    log = open(os.path.join(work, "busbar.log"), "w+")
    proc = subprocess.Popen([ctx.exe], cwd=work, env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        for _ in range(45):
            if proc.poll() is not None:
                break
            try:
                if http_body("http://127.0.0.1:8080/healthz") == "ok":
                    return "the documented minimal config boots and /healthz answers `ok`"
            except (urllib.error.URLError, OSError):
                pass
            time.sleep(2)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.flush()
        log.seek(0)
        tail = log.read()[-4000:]
        log.close()
    raise RowFailure(
        "the quickstart printed in the README and docs/getting-started.md does NOT work for this "
        "artifact: it never booted and answered `ok` on http://127.0.0.1:8080/healthz with the "
        "documented minimal config.yaml. A new user's first five minutes fail on this platform.\n"
        "--- busbar log ---\n%s" % tail
    )


def row_attestation(ctx) -> str:
    if not shutil.which("gh"):
        raise RowFailure(
            "`gh` is not on PATH, so the attestation the docs tell users to verify could not be "
            "verified here. A row that cannot run is RED: an unproven attestation looks like "
            "provenance and is not."
        )
    proc = run(["gh", "attestation", "verify", ctx.archive, "--repo", ctx.repo])
    if proc.returncode != 0:
        raise RowFailure(
            "`gh attestation verify %s --repo %s` failed (exit %d). This is the exact command the "
            "documentation tells users to run, against the exact bytes the release serves.\n%s%s"
            % (os.path.basename(ctx.archive), ctx.repo, proc.returncode, proc.stdout, proc.stderr)
        )
    return "gh attestation verify passes against the released bytes"


def _evidence(ctx, name: str) -> str:
    path = os.path.join(ctx.evidence or "", name)
    if not ctx.evidence or not os.path.isfile(path):
        raise RowFailure(
            "build evidence %r was not produced or not passed to the verifier (looked in %r). "
            "scripts/release-build.sh writes it for EVERY target on the single build path, so its "
            "absence means either the build did not run that path or the evidence did not travel "
            "with the artifact." % (name, ctx.evidence)
        )
    with open(path) as fh:
        return fh.read()


def row_build_evidence(ctx) -> str:
    recorded = _evidence(ctx, "artifact.sha256").split()[0].strip().lower()
    actual = sha256_file(ctx.archive)
    if recorded != actual:
        raise RowFailure(
            "the build recorded SHA-256 %s for the archive it produced, but the archive that was "
            "actually downloaded from the release is %s. Every evidence-based row certifies the "
            "recorded bytes, so an unbound digest would let a build's PGO proof vouch for an "
            "artifact that build never made." % (recorded, actual)
        )
    return "evidence is bound to the shipped bytes (sha256 %s…)" % actual[:16]


def row_pgo_applied(ctx) -> str:
    text = _evidence(ctx, "busbar.pgo-verified")
    fields = dict(
        ln.split("=", 1) for ln in text.splitlines() if "=" in ln and not ln.startswith("#")
    )
    if fields.get("pgo-verified") != "1":
        raise RowFailure("the PGO proof marker is not marked verified:\n%s" % text)
    if fields.get("target") != ctx.target:
        raise RowFailure(
            "the PGO proof marker names target %r but this artifact is %r. A marker from another "
            "leg is not proof about this one." % (fields.get("target"), ctx.target)
        )
    for key in ("profile_bytes", "profraw_count"):
        try:
            value = int(fields.get(key, "0"))
        except ValueError:
            value = 0
        if value <= 0:
            raise RowFailure(
                "the PGO proof marker records %s=%r. A zero here means the trainer flushed nothing "
                "and -Cprofile-use was a no-op, so the shipped binary is not PGO-optimised while "
                "the release claims it is." % (key, fields.get(key))
            )
    return "PGO verified: %s bytes of merged profile from %s .profraw" % (
        fields["profile_bytes"], fields["profraw_count"]
    )



# =================================================================================================
# THE IMAGE ROWS
#
# The image is a DIFFERENT ARTIFACT CLASS from the release tarballs, and it is the one that has
# actually broken in production. busbar 1.5.3's image did not boot under ANY documented invocation
# `USER 65532:65532` against a root-owned `/etc/busbar` in a `FROM scratch` image, so
# the overlay backend was unwritable and boot refused. Every gate was green, because nothing ran the
# image. These rows run it.
#
# ADDRESSED BY DIGEST, NEVER BY TAG. A tag is a moving pointer; verifying `:1.5.4` proves something
# about whatever that name meant at the moment of the pull, which is exactly the property an
# immutable-tag policy exists to stop us relying on. The digest is the artifact.
# =================================================================================================


def _image_ref(ctx) -> str:
    """The digest-pinned reference for the platform under test, or a hard failure."""
    if not getattr(ctx, "image", ""):
        raise AssertionError(
            "no image reference was passed to the verifier (--image), so the image rows could not "
            "run. A row that cannot run is RED, never skipped: these are the rows that would have "
            "caught the release whose image did not boot at all."
        )
    return ctx.image


def _docker(ctx, args: list, timeout: int = 120):
    cmd = ["docker", "run", "--rm", "--platform", ctx.spec["platform"]] + args
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def row_image_boots_documented_quickstart(ctx) -> str:
    """Run the image the way the docs tell a user to run it, and require it to serve."""
    ref = _image_ref(ctx)
    # Run it as a SERVER, which is what the quickstart tells a user to do. An earlier draft of this
    # row ran `--version` and PASSED against the 1.5.3 image -- the very artifact that is known to
    # cannot boot. `--version` prints and exits before the config is loaded, so it proves the binary
    # executes and nothing more. The defect lives in the boot path, so the row has to reach it.
    out = _docker(
        ctx,
        ["-e", "BUSBAR_ADMIN_TOKEN=verify-artifact-probe", "-e", "ANTHROPIC_KEY=verify-artifact-probe", ref],
        timeout=90,
    )
    blob = ((out.stdout or "") + (out.stderr or "")).strip()
    # REACHING `listening` is the property, and it is the ONLY thing this row asserts.
    #
    # An earlier draft also failed on any `[error]` line, which was wrong in both directions. busbar
    # logs a legitimate `[error] auth is DISABLED ... OPEN RELAY` warning on a config that still
    # boots and serves, so that draft failed a working image. And a refusal exits the container
    # while `docker run` can still surface 0, so the exit code alone cannot carry the verdict
    # either. "Did it get to serving?" is the question a user's quickstart actually asks.
    if "listening" not in blob.lower():
        raise AssertionError(
            "the image never reported listening, so it did not reach the serving state the "
            "quickstart tells a user to expect. 1.5.3's image refused every "
            "documented form because the overlay backend was unwritable for the non-root UID it "
            "ships.\n  exit=%d\n  %s" % (out.returncode, blob[:600])
        )
    return "boots and listens under the documented invocation"


def row_image_runs_as_nonroot(ctx) -> str:
    """The image must not run as root.

    Stated as its own row because the OBVIOUS repair for a boot failure is to run as root, which
    would turn this contract green while trading a boot bug for a privilege regression. Read from
    the image config rather than from the Dockerfile: the Dockerfile is the intent, the config is
    what ships.
    """
    ref = _image_ref(ctx)
    out = run(["docker", "image", "inspect", "--format", "{{.Config.User}}", ref])
    user = (out.stdout or "").strip()
    if out.returncode != 0:
        raise AssertionError("could not inspect the image config: %s" % (out.stderr or "").strip()[:300])
    if user in ("", "root", "0", "0:0"):
        raise AssertionError(
            "the image runs as %r. It ships a non-root UID deliberately, and restoring boot by "
            "running as root would look identical in CI while removing that property."
            % (user or "<unset, which means root>")
        )
    return "runs as %s" % user


def row_image_release_pubkey(ctx) -> str:
    """The image carries its OWN musl build, so the tarballs' key proves nothing about it."""
    ref = _image_ref(ctx)
    if not ctx.pubkey:
        raise AssertionError("no --pubkey was supplied, so this row could not run. Unknown is not green.")
    out = _docker(ctx, ["-e", "BUSBAR_ADMIN_TOKEN=verify-artifact-probe", ref, "--list-plugins"])
    blob = (out.stdout or "") + (out.stderr or "")
    if "embeds no busbar release key" in blob:
        raise AssertionError(
            "the image's binary embeds NO release public key, so it refuses every correctly-signed "
            "first-party plugin. `option_env!(\"BUSBAR_RELEASE_PUBKEY\")` is read at COMPILE time "
            "and fails silently to None: the image build must carry the variable. This is the "
            "aarch64 defect, in the other artifact class."
        )
    if out.returncode != 0:
        raise AssertionError(
            "could not read the plugin surface from the image: exit=%d %s"
            % (out.returncode, blob.strip()[:300])
        )
    return "the image's binary carries a release key"


def row_image_version_anchored(ctx) -> str:
    """Read the version from the RUNNING image, anchored, so 1.5.4 is not satisfied by 1.5.40."""
    ref = _image_ref(ctx)
    out = _docker(ctx, ["-e", "BUSBAR_ADMIN_TOKEN=verify-artifact-probe", ref, "--version"])
    text = ((out.stdout or "") + (out.stderr or "")).strip()
    if not re.search(r"(?<![0-9.])%s(?![0-9.])" % re.escape(ctx.version), text):
        raise AssertionError(
            "the image reports %r, which does not contain the anchored version %r. Anchored so a "
            "1.5.4 release cannot be satisfied by a 1.5.40 binary."
            % (text[:200], ctx.version)
        )
    return "reports %s" % ctx.version


CHECKS = {
    "archive_shape": row_archive_shape,
    "binary_format": row_binary_format,
    "release_pubkey": row_release_pubkey,
    "first_party_plugin": row_first_party_plugin,
    "version_anchored": row_version_anchored,
    "quickstart_boots": row_quickstart_boots,
    "attestation": row_attestation,
    "build_evidence": row_build_evidence,
    "pgo_applied": row_pgo_applied,
    "image_boots_documented_quickstart": row_image_boots_documented_quickstart,
    "image_runs_as_nonroot": row_image_runs_as_nonroot,
    "image_release_pubkey": row_image_release_pubkey,
    "image_version_anchored": row_image_version_anchored,
}


# =================================================================================================
# CONTRACT WHOLENESS, ROW SELECTION, AND THE RUN
# =================================================================================================


def _assert_contract_is_whole(contract: dict) -> list:
    """SET EQUALITY between the declared rows and the implemented checks, plus a count floor.

    A loop over a discovered set with no floor passes when the set is empty, so a truncated or
    empty contract file would otherwise verify every artifact against nothing and report green."""
    rows = contract.get("rows") or []
    declared = [r["id"] for r in rows]
    if len(declared) != len(set(declared)):
        raise SystemExit("contract: duplicate row ids in %r" % declared)
    floor = int(contract.get("min_rows", 0))
    if floor <= 0:
        raise SystemExit("contract: min_rows must be a positive floor; got %r" % contract.get("min_rows"))
    if len(rows) < floor:
        raise SystemExit(
            "contract: %d rows declared, floor is %d. Verifying an artifact against fewer rows than "
            "the contract promises is a check that passes without executing." % (len(rows), floor)
        )
    missing = sorted(set(declared) - set(CHECKS))
    orphan = sorted(set(CHECKS) - set(declared))
    if missing:
        raise SystemExit(
            "contract: rows %s are declared in artifact-contract.json with no implementation in "
            "verify-artifact.py. A declared-but-unimplemented row is a property everybody believes "
            "is checked and nobody checks." % missing
        )
    if orphan:
        raise SystemExit(
            "contract: checks %s are implemented in verify-artifact.py but declared nowhere in "
            "artifact-contract.json. The contract is supposed to be the readable statement of what "
            "ships; a check outside it is invisible to everyone reading the contract." % orphan
        )
    return rows


def applies(row: dict, spec: dict) -> bool:
    """A row applies unless its `applies_when` disagrees with the target's OWN declaration."""
    for key, want in (row.get("applies_when") or {}).items():
        if key not in spec:
            raise SystemExit(
                "contract row %r gates on %r, which no target declares in release-targets.json. A "
                "gate on an absent field silently switches the row off for every target."
                % (row["id"], key)
            )
        if spec[key] != want:
            return False
    return True


class Ctx:
    pass


def selftest() -> int:
    """Prove the CONTRACT-WHOLENESS guards discriminate, by constructing each failure state.

    Without this the guards are only ever exercised by a well-formed contract, so they would look
    identical to guards that parse nothing and return the rows unchanged. Every case below asserts
    that a SPECIFIC malformation is refused; a case that stops failing means the guard it covers has
    silently stopped guarding.

    The row implementations themselves are not exercised here — they need a real artifact, and the
    honest proof for those is running the verifier against one. That has been done against real
    released bytes: busbar 1.5.3's aarch64-unknown-linux-gnu artifact FAILS `release_pubkey` and its
    x86_64-unknown-linux-gnu artifact PASSES it, which is this file catching the exact defect that
    motivated it, on production artifacts rather than fixtures.
    """
    # EVERY implemented check, because set equality runs both ways: a "well-formed" fixture that
    # declared only some of them would be refused as orphaning the rest — which is the guard working,
    # and would have made the control case fail for the wrong reason.
    all_ids = list(CHECKS)
    good = {"min_rows": len(all_ids), "rows": [{"id": rid} for rid in all_ids]}
    cases = []

    def case(name, contract, want_fail, why):
        cases.append((name, contract, want_fail, why))

    case("a whole contract", good, False, "the well-formed case must pass, or every case below is vacuous")
    case(
        "min_rows absent",
        {"rows": good["rows"]},
        True,
        "a contract with no floor verifies against however many rows survive a bad edit",
    )
    case(
        "min_rows zero",
        {"min_rows": 0, "rows": good["rows"]},
        True,
        "a floor of zero is not a floor; an empty contract would then verify everything against nothing",
    )
    case(
        "fewer rows than the floor",
        {"min_rows": len(all_ids) + 3, "rows": good["rows"]},
        True,
        "a truncated contract must be refused rather than quietly checking less",
    )
    case(
        "a declared row with no implementation",
        {"min_rows": 1, "rows": [{"id": "no_such_row_is_implemented"}]},
        True,
        "a declared-but-unimplemented row is a property everybody believes is checked and nobody checks",
    )
    case(
        "an implemented check declared nowhere",
        {"min_rows": 1, "rows": [{"id": all_ids[0]}]},
        True,
        "set equality runs BOTH ways: a check outside the contract is invisible to anyone reading it",
    )
    case(
        "duplicate row ids",
        {"min_rows": 2, "rows": [{"id": all_ids[0]}, {"id": all_ids[0]}]},
        True,
        "a duplicated id can satisfy a count floor while covering fewer properties than it claims",
    )

    failures = 0
    for name, contract, want_fail, why in cases:
        try:
            _assert_contract_is_whole(contract)
            got_fail = False
        except SystemExit:
            got_fail = True
        ok = got_fail == want_fail
        if not ok:
            failures += 1
        print(
            "  [%s] %-38s -> %s (expected %s)\n         %s"
            % ("ok" if ok else "FAILED", name,
               "refused" if got_fail else "accepted",
               "refused" if want_fail else "accepted", why)
        )

    # `applies_when` gating on a field no target declares would switch a row off for EVERY target
    # while looking like a deliberate exemption. Proven rather than asserted.
    try:
        applies({"id": "x", "applies_when": {"a_field_no_target_declares": True}}, {"target": "t"})
        print("  [FAILED] applies_when on an undeclared field was accepted")
        failures += 1
    except SystemExit:
        print("  [ok] %-38s -> refused (a gate on an absent field silently disables the row)"
              % "applies_when on an undeclared field")

    total = len(cases) + 1
    if failures:
        print("\nSELF-TEST FAILED: %d of %d checks did not hold" % (failures, total), file=sys.stderr)
        return 1
    print("\nself-test: %d checks, all hold" % total)
    return 0


def main(argv=None) -> int:
    if "--selftest" in (argv if argv is not None else sys.argv[1:]):
        return selftest()
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--selftest", action="store_true",
                    help="prove the contract-wholeness guards discriminate, then exit")
    ap.add_argument("--archive", default="", help="the artifact AS DOWNLOADED FROM THE RELEASE")
    ap.add_argument("--target", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--pubkey", default=os.environ.get("BUSBAR_RELEASE_PUBKEY", ""))
    ap.add_argument("--plugin", default="", help="the signed first-party plugin tarball for this target")
    ap.add_argument("--image", default="",
                    help="DIGEST-PINNED image reference for an image target. A tag is a moving "
                         "pointer, so verifying one proves something about whatever that name meant "
                         "at the moment of the pull; the digest is the artifact.")
    ap.add_argument("--evidence", default="", help="directory holding this build's evidence files")
    ap.add_argument("--repo", default="GetBusbar/busbar")
    ap.add_argument("--repo-root", default=ROOT)
    ap.add_argument("--targets", default=DEFAULT_TARGETS)
    ap.add_argument("--contract", default=DEFAULT_CONTRACT)
    ap.add_argument(
        "--rows",
        default="",
        help="LOCAL USE ONLY: run only these row ids. The verdict is PARTIAL and the exit code is "
             "2, never 0, so it can never be wired in as a pass.",
    )
    a = ap.parse_args(argv)

    contract = json.load(open(a.contract, encoding="utf-8"))
    targets = json.load(open(a.targets, encoding="utf-8"))
    rows = _assert_contract_is_whole(contract)

    specs = {t["target"]: t for t in targets["targets"]}
    if a.target not in specs:
        raise SystemExit(
            "target %r is not declared in %s. The verify matrix is enumerated from that file, so an "
            "undeclared target is an artifact nothing produced or nothing owes."
            % (a.target, a.targets)
        )
    spec = specs[a.target]

    applicable = [r for r in rows if applies(r, spec)]
    selected = applicable
    if a.rows:
        want = {s.strip() for s in a.rows.split(",") if s.strip()}
        unknown = sorted(want - {r["id"] for r in applicable})
        if unknown:
            raise SystemExit("--rows names %s, which do not apply to %s" % (unknown, a.target))
        selected = [r for r in applicable if r["id"] in want]

    work = tempfile.mkdtemp(prefix="busbar-verify-artifact-")
    ctx = Ctx()
    ctx.archive, ctx.target, ctx.version = os.path.abspath(a.archive), a.target, a.version
    ctx.pubkey, ctx.repo, ctx.spec, ctx.targets = a.pubkey, a.repo, spec, targets
    ctx.plugin = os.path.abspath(a.plugin) if a.plugin else ""
    ctx.image = a.image
    ctx.evidence = os.path.abspath(a.evidence) if a.evidence else ""
    ctx.repo_root, ctx.work = os.path.abspath(a.repo_root), work

    print("=== artifact contract: %s ===" % a.target)
    print("archive : %s" % ctx.archive)
    print("runner  : %s (%s)" % (spec["runner"], sys.platform))
    print("rows    : %d applicable of %d declared\n" % (len(applicable), len(rows)))

    # Unpacking is a precondition of most rows, so it happens once and its own assertions live in
    # `archive_shape`. A failure here is reported as that row rather than as a crash.
    unpack = os.path.join(work, "unpack")
    os.makedirs(unpack, exist_ok=True)
    ctx.members, unpack_error = [], None
    # An IMAGE has no archive to unpack: its rows address it by digest and run it. Guarding on the
    # target's own declared `kind` rather than on "did an --archive happen to be passed" keeps the
    # decision in release-targets.json, where every other per-class difference already lives.
    if spec.get("kind") == "image":
        pass
    else:
        try:
            ctx.members = extract_archive(ctx.archive, unpack)
        except (RowFailure, tarfile.TarError, zipfile.BadZipFile, OSError) as exc:
            unpack_error = "the archive could not be unpacked: %s" % exc
    ctx.exe = os.path.join(unpack, spec["exe"])
    if os.path.exists(ctx.exe):
        os.chmod(ctx.exe, 0o755)

    failures, results = [], []
    for row in selected:
        try:
            if unpack_error:
                raise RowFailure(unpack_error)
            note = CHECKS[row["id"]](ctx)
            results.append((row["id"], "PASS", note))
        except RowFailure as exc:
            results.append((row["id"], "FAIL", str(exc)))
            failures.append(row["id"])
        except Exception as exc:  # a crashing check is a failing check, never a skipped one
            results.append((row["id"], "FAIL", "%s: %s" % (type(exc).__name__, exc)))
            failures.append(row["id"])

    for rid, verdict, note in results:
        print("%-4s %-20s %s" % (verdict, rid, note.splitlines()[0] if note else ""))
        if verdict == "FAIL":
            for line in note.splitlines()[1:]:
                print("       %s" % line)

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("### artifact contract - `%s`\n\n| row | verdict |\n| --- | --- |\n" % a.target)
            for rid, verdict, _ in results:
                fh.write("| `%s` | %s |\n" % (rid, verdict))
            fh.write("\n")

    shutil.rmtree(work, ignore_errors=True)

    if a.rows:
        print(
            "\nPARTIAL: %d of %d applicable rows were run because --rows was passed. This verdict "
            "is never green." % (len(selected), len(applicable))
        )
        return 2
    if failures:
        print(
            "\n::error::ARTIFACT CONTRACT FAILED for %s: %s. The contract is 100%% or 0%% -- this "
            "artifact must not ship, and neither must the release it belongs to."
            % (a.target, ", ".join(failures))
        )
        return 1
    print("\nPASS: all %d applicable contract rows hold for %s." % (len(applicable), a.target))
    return 0


if __name__ == "__main__":
    sys.exit(main())
