"""Host-side Linux job storage and user-namespace contract.

The protected controller runs as host root, on the Docker host. Provision a fresh
filesystem with ``prepare`` before staging checkout/work; ``dispose`` unmounts it only
after all candidate containers have been removed. No privilege enters candidates.
Docker must be a dedicated daemon configured with userns-remap. Its subordinate
UID/GID ranges are pinned in the protected configuration, never auto-selected.

Usage (on that same Linux host):
  python3 linux_job_isolation.py prepare /protected/runtime.json
  # Stage checkout/work below isolation.storage_root, then run native admission.
  python3 linux_job_isolation.py dispose /protected/runtime.json

The configuration is the native-confinement/2 JSON and includes an ``isolation``
object with storage_kind (tmpfs or loop-ext4), storage_root, storage_bytes,
storage_inodes, storage_reserve_bytes and uid_map/gid_map
triples [0, subordinate_host_start, range_length]. Source and controller files
may share the quota, but controller roots must never be candidate mounts. The
controller owns preparation/disposal; it must finish container disposal first.
Per-container /tmp and /dev/shm have additional caps in native_confinement.py.
Disk-backed jobs additionally pin storage_image, a fresh sibling file under the
root-owned job directory. Preallocation reserves the entire budget before any
candidate starts; ext4 metadata means usable capacity is slightly smaller.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time


HOST_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


def kernel_no_swap():
    """Observe zero host swap capacity; confined processes cannot add backing."""
    snapshots = {}
    for name in ('swaps', 'meminfo'):
        with Path('/proc/' + name).open('rb') as stream:
            snapshots[name] = stream.read(65537)
        if len(snapshots[name]) > 65536:
            raise ValueError('kernel swap evidence exceeds bound')
    swaps = snapshots['swaps'].splitlines()
    totals = [line for line in snapshots['meminfo'].splitlines() if line.startswith(b'SwapTotal:')]
    if (len(swaps) != 1 or swaps[0].split() != [b'Filename', b'Type', b'Size', b'Used', b'Priority']
            or len(totals) != 1 or totals[0].split() != [b'SwapTotal:', b'0', b'kB']):
        raise ValueError('runtime swap is unbounded: kernel has swap capacity or invalid evidence')
    return {'mechanism': 'kernel-zero-swap-capacity', 'effective_swap_bytes': 0,
            'proc_swaps': snapshots['swaps'].decode('ascii'),
            'proc_swaps_sha256': hashlib.sha256(snapshots['swaps']).hexdigest(),
            'swap_total_entry': totals[0].decode('ascii'),
            'swap_total_entry_sha256': hashlib.sha256(totals[0]).hexdigest()}


def validate_swap_bound(daemon, host, required_memory):
    """Require exact RAM and zero swap, including kernels without swap accounting."""
    if (type(required_memory) is not int or required_memory <= 0
            or type(host.get('Memory')) is not int or host['Memory'] != required_memory):
        raise ValueError('runtime Memory differs from the protected RAM bound')
    observed = host.get('MemorySwap')
    if (daemon.get('SwapLimit') is True and type(observed) is int
            and observed == required_memory):
        proof = {'mechanism': 'docker-memory-swap-limit', 'effective_swap_bytes': 0}
    elif (daemon.get('SwapLimit') is False and type(observed) is int
            and observed in (required_memory, -1)):
        proof = kernel_no_swap()
        proof['daemon_swap_limit'] = False
    else:
        raise ValueError('runtime MemorySwap/SwapLimit do not prove the protected no-swap request')
    proof.update(requested_memory_swap_bytes=required_memory, observed_memory_swap_bytes=observed)
    return proof


def recheck_swap_bound(proof):
    """Reobserve host backing after disposal when no kernel swap controller exists."""
    if proof.get('mechanism') == 'kernel-zero-swap-capacity':
        proof['after_disposal'] = kernel_no_swap()

def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_configuration(config):
    require(isinstance(config, dict), "invalid Linux isolation configuration")
    kind = config.get("storage_kind")
    require(kind in ("tmpfs", "loop-ext4"), "unknown job storage kind")
    keys = {"storage_kind", "storage_root", "storage_bytes", "storage_inodes",
            "storage_reserve_bytes", "uid_map", "gid_map"}
    require(set(config) == keys | ({"storage_image"} if kind == "loop-ext4" else set()),
            "invalid Linux isolation configuration")
    root = Path(config["storage_root"])
    require(root.is_absolute() and len(root.parts) > 2 and root == root.resolve()
            and not root.is_symlink() and "," not in str(root), "unsafe job storage root")
    require(type(config["storage_bytes"]) is int
            and 4096 <= config["storage_bytes"] <= 256 * 1024**3
            and config["storage_bytes"] % 4096 == 0,
            "invalid job storage byte cap")
    require(type(config["storage_inodes"]) is int
            and 16 <= config["storage_inodes"] <= 16 * 1024**2,
            "invalid job storage inode cap")
    reserve = config["storage_reserve_bytes"]
    require(type(reserve) is int and 0 <= reserve <= 256 * 1024**3,
            "invalid host storage reserve")
    if kind == "loop-ext4":
        image = Path(config["storage_image"])
        require(image.is_absolute() and image == image.resolve()
                and not image.is_symlink() and image.parent == root.parent
                and image != root, "job image must be a direct protected sibling")
        require(config["storage_bytes"] >= 64 * 1024**2
                and config["storage_inodes"] >= 128 and reserve > 0,
                "invalid ext4 job storage budget")
    for key in ("uid_map", "gid_map"):
        row = config[key]
        require(isinstance(row, list) and len(row) == 3
                and all(type(n) is int for n in row) and row[0] == 0
                and row[1] >= 65536 and 1 <= row[2] <= 2**31
                and row[1] + row[2] < 2**32,
                "invalid subordinate identity map")
    return root


def mount_rows():
    def unescape(value):
        return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), value)

    rows = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        before, after = line.split(" - ", 1)
        fields, filesystem = before.split(), after.split()
        rows.append({"root": unescape(fields[3]), "path": Path(unescape(fields[4])),
                     "options": set(fields[5].split(",")), "type": filesystem[0],
                     "source": unescape(filesystem[1])})
    return rows


def protected_image_parent(config):
    parent = Path(config["storage_image"]).parent
    metadata = parent.stat()
    require(parent.is_dir() and metadata.st_uid == 0
            and metadata.st_mode & 0o022 == 0, "job image parent is not protected")
    return parent


def available_bytes(path):
    capacity = os.statvfs(path)
    return capacity.f_bavail * capacity.f_frsize


def loop_rows(*selection):
    result = subprocess.run(["losetup", "--json", "--list", "--output",
                             "NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN,SIZELIMIT,OFFSET,RO",
                             *selection], check=True, capture_output=True, text=True, env=HOST_ENV)
    return json.loads(result.stdout)["loopdevices"]


def validate_loop(config, source):
    protected_image_parent(config)
    image = Path(config["storage_image"])
    metadata = image.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
            and metadata.st_uid == 0 and metadata.st_mode & 0o077 == 0
            and metadata.st_size == config["storage_bytes"]
            and metadata.st_blocks * 512 >= metadata.st_size,
            "job image is not a private preallocated regular file")
    require(re.fullmatch(r"/dev/loop[0-9]+", source), "job filesystem is not a loop device")
    rows = loop_rows(source)
    device = f"{os.major(metadata.st_dev)}:{os.minor(metadata.st_dev)}"
    require(len(rows) == 1 and rows[0]["name"] == source
            and rows[0]["back-file"] == str(image)
            and rows[0]["back-ino"] == metadata.st_ino
            and rows[0]["back-maj:min"] == device
            and rows[0]["offset"] == 0 and rows[0]["ro"] is False
            and rows[0]["sizelimit"] == config["storage_bytes"],
            "job loop device backing identity or limit differs")
    return source


def validate_storage(config, writable_paths):
    root = validate_configuration(config)
    require(os.geteuid() == 0, "Linux isolation controller must run as host root")
    require(root.is_dir(), "job storage root missing")
    rows = mount_rows()
    exact = [row for row in rows if row["path"] == root]
    filesystem = "ext4" if config["storage_kind"] == "loop-ext4" else "tmpfs"
    require(len(exact) == 1 and exact[0]["type"] == filesystem
            and exact[0]["root"] == "/"
            and {"rw", "nosuid", "nodev"} <= exact[0]["options"],
            "job storage must be a dedicated bounded filesystem")
    require(not any(row["path"] != root and row["path"].is_relative_to(root)
                    for row in rows), "nested mount bypasses job storage quota")
    if filesystem == "ext4":
        validate_loop(config, exact[0]["source"])
    capacity = os.statvfs(root)
    byte_cap = capacity.f_blocks * capacity.f_frsize
    require(0 < byte_cap <= config["storage_bytes"]
            and 0 < capacity.f_files <= config["storage_inodes"],
            "job storage exceeds byte or inode quota")
    for value in writable_paths:
        path = Path(value)
        require(path.is_dir() and path == path.resolve() and not path.is_symlink()
                and path != root and path.is_relative_to(root),
                "writable bind escapes job storage quota")
        require(path.stat().st_dev == root.stat().st_dev,
                "writable bind uses another filesystem")
    return {"root": str(root), "bytes": byte_cap, "inodes": capacity.f_files,
            "filesystem": filesystem}


def prepare_writable(config, writable_paths, uid, gid):
    """Grant the remapped candidate ownership without following candidate links."""
    observation = validate_storage(config, writable_paths)
    require(type(uid) is int and 0 < uid < config["uid_map"][2]
            and type(gid) is int and 0 < gid < config["gid_map"][2],
            "candidate identity outside subordinate map")
    mapped_uid, mapped_gid = config["uid_map"][1] + uid, config["gid_map"][1] + gid
    # Called only while the prior candidate is stopped/disposed. fwalk's dir_fd
    # anchors traversal; symbolic links and special files are never followed.
    for value in writable_paths:
        path = Path(value)
        os.chown(path, mapped_uid, mapped_gid, follow_symlinks=False)
        for _, directories, files, fd in os.fwalk(path, follow_symlinks=False):
            for name in directories + files:
                metadata = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode):
                    if (metadata.st_uid, metadata.st_gid) == (mapped_uid, mapped_gid):
                        continue
                    require(not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink == 1,
                            "hard-linked candidate output cannot be reowned")
                    os.chown(name, mapped_uid, mapped_gid, dir_fd=fd, follow_symlinks=False)
    return observation


def validate_userns(config, daemon, inspected=None):
    validate_configuration(config)
    require("name=userns" in daemon.get("SecurityOptions", []),
            "Docker daemon requires userns-remap")
    if inspected is not None:
        require(inspected["HostConfig"].get("UsernsMode", "") == "",
                "candidate must inherit the remapped user namespace")
    return {"uid_map": config["uid_map"], "gid_map": config["gid_map"]}


def prepare(config):
    root = validate_configuration(config)
    require(os.geteuid() == 0, "job storage preparation requires host root")
    require(not root.exists(), "job storage must be fresh")
    image, loop = None, None
    if config["storage_kind"] == "loop-ext4":
        parent = protected_image_parent(config)
        require(available_bytes(parent) >= config["storage_bytes"] + config["storage_reserve_bytes"],
                "insufficient host disk capacity after required reserve")
        require(not Path(config["storage_image"]).exists(), "job storage image must be fresh")
    root.mkdir(mode=0o755)
    try:
        if config["storage_kind"] == "tmpfs":
            subprocess.run(["mount", "-t", "tmpfs", "-o",
                            f"nosuid,nodev,size={config['storage_bytes']},nr_inodes={config['storage_inodes']},mode=0755",
                            "busbar-job", str(root)], check=True, env=HOST_ENV)
        else:
            path = Path(config["storage_image"])
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            image = path
            os.close(descriptor)
            subprocess.run(["fallocate", "--length", str(config["storage_bytes"]), str(image)], check=True, env=HOST_ENV)
            require(available_bytes(image.parent) >= config["storage_reserve_bytes"],
                    "host disk reserve consumed during allocation")
            # Round down to ext4's per-block-group inode granularity. The final
            # statvfs check enforces the actual count, rather than trusting -N.
            groups = (config["storage_bytes"] + 128 * 1024**2 - 1) // (128 * 1024**2)
            inodes = config["storage_inodes"] // (groups * 8) * (groups * 8)
            require(inodes >= 128, "inode cap too small for ext4 geometry")
            subprocess.run(["mkfs.ext4", "-q", "-b", "4096", "-g", "32768", "-m", "0",
                            "-N", str(inodes), "-E", "nodiscard,lazy_itable_init=0,lazy_journal_init=0",
                            str(image)], check=True, env=HOST_ENV)
            # Some backing filesystems release zeroed mkfs ranges even with
            # nodiscard. Re-reserve them before exposing the filesystem.
            subprocess.run(["fallocate", "--length", str(config["storage_bytes"]), str(image)], check=True, env=HOST_ENV)
            require(available_bytes(image.parent) >= config["storage_reserve_bytes"],
                    "host disk reserve consumed while formatting")
            loop = subprocess.check_output(["losetup", "--find", "--show", "--nooverlap",
                                            "--sizelimit", str(config["storage_bytes"]), str(image)],
                                           text=True, env=HOST_ENV).strip()
            validate_loop(config, loop)
            subprocess.run(["mount", "-t", "ext4", "-o", "nosuid,nodev,nodiscard", loop, str(root)], check=True, env=HOST_ENV)
        observation = validate_storage(config, [])
        if image is not None:
            observation.update(image_bytes=config["storage_bytes"],
                               host_available_bytes=available_bytes(image.parent),
                               host_reserve_bytes=config["storage_reserve_bytes"])
        return observation
    except BaseException:
        if os.path.ismount(root):
            subprocess.run(["umount", str(root)], check=True, env=HOST_ENV)
        if loop is not None:
            detach_loop(loop, image)
        if image is not None:
            image.unlink()
        root.rmdir()
        raise


def detach_loop(loop, image):
    subprocess.run(["losetup", "--detach", loop], check=True, env=HOST_ENV)
    # Detach may defer release while another namespace retains a bind. Keep the
    # backing image until the kernel confirms there is no remaining association.
    for _ in range(40):
        if not loop_rows("--associated", str(image)):
            return
        time.sleep(0.05)
    raise ValueError("job loop device is still in use")


def dispose(config):
    root = validate_configuration(config)
    validate_storage(config, [])
    loop = None
    if config["storage_kind"] == "loop-ext4":
        loop = next(row["source"] for row in mount_rows() if row["path"] == root)
    # The caller must confirm container disposal first: another mount namespace
    # may retain a bind even after this namespace unmounts its source. Do not
    # conceal local busy mounts with lazy/forced unmount.
    subprocess.run(["umount", str(root)], check=True, env=HOST_ENV)
    require(not os.path.ismount(root), "job storage disposal was not confirmed")
    if loop is not None:
        image = Path(config["storage_image"])
        detach_loop(loop, image)
        image.unlink()
    root.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "dispose"))
    parser.add_argument("configuration", type=Path)
    args = parser.parse_args()
    config = json.loads(args.configuration.read_text())["isolation"]
    result = prepare(config) if args.action == "prepare" else dispose(config)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
