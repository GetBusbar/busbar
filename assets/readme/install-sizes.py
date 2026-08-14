#!/usr/bin/env python3
"""Measure what you actually install, and write install.json.

The README's performance and memory figures come from onthebench.ai (see generate.py). These do NOT:
an image size is a registry fact, not a load test, so it is a SEPARATE instrument and carries its own
stamp. Folding it into data.json would let one date stand for two measurements taken months apart.

  python3 assets/readme/install-sizes.py            # re-measure from the registries, rewrite install.json
  python3 assets/readme/install-sizes.py --check    # exit 1 if the checked-in file disagrees

Compressed layer blobs are summed, which is what a `docker pull` transfers and what the registry
stores. Only the manifests and the tiny config blob are fetched; no image is pulled.

One field cannot be measured this way and says so in the file: the size of a `pip install` into a
clean virtualenv. It needs a real install on a real machine, so it is carried with the command that
produced it and the date it was run, and `--check` deliberately does not re-derive it.
"""
import json, os, sys, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "install.json")

IDX = ("application/vnd.oci.image.index.v1+json,"
       "application/vnd.docker.distribution.manifest.list.v2+json")
MAN = ("application/vnd.oci.image.manifest.v1+json,"
       "application/vnd.docker.distribution.manifest.v2+json")

# (key, registry host, repository, tag, the platform the README compares on)
IMAGES = [
    ("busbar", "registry-1.docker.io", "getbusbar/busbar", "latest", "amd64"),
    ("litellm", "ghcr.io", "berriai/litellm", "main-latest", "amd64"),
]


def token(host, repo):
    """Anonymous pull token. Docker Hub and GHCR use different auth endpoints, same bearer shape."""
    if host == "ghcr.io":
        url = f"https://ghcr.io/token?scope=repository:{repo}:pull&service=ghcr.io"
    else:
        url = (f"https://auth.docker.io/token?service=registry.docker.io"
               f"&scope=repository:{repo}:pull")
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.load(r)["token"]


def fetch(host, repo, ref, tok, accept):
    req = urllib.request.Request(
        f"https://{host}/v2/{repo}/manifests/{ref}",
        headers={"Authorization": "Bearer " + tok, "Accept": accept})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def measure(key, host, repo, tag, arch):
    tok = token(host, repo)
    idx = fetch(host, repo, tag, tok, IDX + "," + MAN)
    if idx.get("manifests"):  # multi-arch index: pick the platform the comparison is stated on
        digest = next(m["digest"] for m in idx["manifests"]
                      if m.get("platform", {}).get("os") == "linux"
                      and m["platform"].get("architecture") == arch)
        man = fetch(host, repo, digest, tok, MAN)
    else:
        man = idx
    layers = man["layers"]
    total = sum(l["size"] for l in layers)
    return {
        "image": f"{repo}:{tag}",
        "platform": f"linux/{arch}",
        "compressed_bytes": total,
        # BOTH units, spelled correctly, because they differ by 5% and the README quotes one of them.
        # (The site's metrics/measure.sh writes `busbar.docker.compressed_mb: 5.74`, which is 1024-based
        # and therefore MiB under an SI name; the README inherited that figure and its label. The
        # numbers were never wrong against each other -- both sides were MiB -- but "MB" was.)
        # Compressed blobs: what the pull transfers. Not the uncompressed on-disk rootfs.
        "compressed_mib": round(total / 1048576, 2),
        "compressed_mb": round(total / 1e6, 2),
        "layers": len(layers),
    }


def main():
    check = "--check" in sys.argv
    prev = {}
    if os.path.exists(OUT):
        prev = json.load(open(OUT))

    images = {k: measure(k, h, r, t, a) for k, h, r, t, a in IMAGES}

    out = {
        "_generator": "assets/readme/install-sizes.py",
        "images": images,
        # Carried, not derived. `--check` compares the registry figures above and leaves these alone,
        # because re-deriving them means running the install, which this script does not do.
        "hand_measured": prev.get("hand_measured") or {
            "busbar_binary_mib": None,
            "litellm_venv_mib": None,
            "litellm_venv_packages": None,
            "command": "pip install 'litellm[proxy]' into a clean virtualenv",
            "measured_at": None,
        },
    }

    if check:
        if not prev:
            print(f"{OUT} is missing; run: python3 assets/readme/install-sizes.py", file=sys.stderr)
            return 1
        if prev.get("images") != images:
            print(f"{OUT} disagrees with the registries; run: "
                  f"python3 assets/readme/install-sizes.py", file=sys.stderr)
            for k in images:
                if prev.get("images", {}).get(k) != images[k]:
                    print(f"  {k}: {prev.get('images', {}).get(k)} -> {images[k]}", file=sys.stderr)
            return 1
        print("install.json agrees with the registries")
        return 0

    json.dump(out, open(OUT, "w"), indent=1)
    open(OUT, "a").write("\n")
    print(f"wrote {OUT}")
    for k, v in images.items():
        print(f"  {k}: {v['compressed_mb']} MB across {v['layers']} layers ({v['platform']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
