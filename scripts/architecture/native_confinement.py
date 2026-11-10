"""Explicit candidate execution boundary; controller code never enters its mounts.

Opt-in through a protected digest-pinned runtime configuration. Missing images,
unsupported fixtures or failed disposal refuse; there is no host fallback.
"""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import uuid


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def checked_directory(value):
    path = Path(value)
    require(
        path.is_absolute()
        and path.is_dir()
        and not path.is_symlink()
        and path == path.resolve()
        and len(path.parts) > 2,
        "unsafe execution root",
    )
    require("," not in str(path), "unsupported mount path")
    return path


def writable_directory(root, *parts):
    current = checked_directory(root)
    for part in parts:
        require(
            part not in ("", ".", "..") and "/" not in part,
            "invalid writable directory component",
        )
        current = current / part
        require(not current.is_symlink(), "indirect writable directory")
        current.mkdir(exist_ok=True)
        checked_directory(current)
    return current


class Execution:
    def __init__(self, config, roots, control):
        require(
            set(config)
            == {
                "schema",
                "docker",
                "docker_sha256",
                "docker_host",
                "image",
                "runtime",
                "uid",
                "gid",
                "python",
                "environment",
                "resources",
            },
            "unknown isolation configuration",
        )
        require(
            config["schema"] == "busbar.native-confinement/1",
            "unknown isolation schema",
        )
        require(
            Path(config["docker"]).is_absolute()
            and digest(config["docker"]) == config["docker_sha256"],
            "Docker client is not the pinned executable",
        )
        require(
            re.fullmatch(r"unix:///[^\s,]+", config["docker_host"]),
            "local Unix Docker endpoint required",
        )
        require(
            re.fullmatch(r"[a-z0-9./:_-]+@sha256:[0-9a-f]{64}", config["image"]),
            "immutable toolchain image required",
        )
        require(config["runtime"] in ("runc", "runsc"), "unsupported candidate runtime")
        require(
            type(config["uid"]) is int
            and config["uid"] > 0
            and type(config["gid"]) is int
            and config["gid"] > 0,
            "candidate must use a nonroot identity",
        )
        require(
            Path(config["python"]).is_absolute(), "pinned-image Python path required"
        )
        require(
            set(config["environment"])
            <= {"PATH", "CARGO_HOME", "RUSTUP_HOME", "GOROOT", "RUSTC", "RUSTDOC"}
            and "PATH" in config["environment"]
            and all(isinstance(v, str) for v in config["environment"].values()),
            "unexpected toolchain environment",
        )
        resources = config["resources"]
        require(
            set(resources) == {"cpus", "memory_bytes", "pids"}
            and all(type(v) is int and v > 0 for v in resources.values())
            and resources["cpus"] <= 64
            and resources["memory_bytes"] <= 256 * 1024**3
            and resources["pids"] <= 65536,
            "invalid confinement resource caps",
        )
        self.config = config
        self.control = checked_directory(control)
        require(
            set(roots) == {"checkout", "candidate", "trusted", "harness"},
            "unexpected execution roots",
        )
        self.roots = {name: checked_directory(path) for name, path in roots.items()}
        for name in ("checkout", "candidate"):
            require(
                not self.control.is_relative_to(self.roots[name]),
                "controller is beneath candidate access",
            )
        for name in ("trusted", "harness"):
            require(
                not self.control.is_relative_to(self.roots[name]),
                "controller is exposed through readonly root",
            )
            for writable in ("checkout", "candidate"):
                require(
                    not self.roots[name].is_relative_to(self.roots[writable])
                    and not self.roots[writable].is_relative_to(self.roots[name]),
                    "trusted source overlaps candidate roots",
                )
        require(
            not self.roots["candidate"].is_relative_to(self.roots["checkout"])
            and not self.roots["checkout"].is_relative_to(self.roots["candidate"]),
            "candidate roots overlap",
        )
        source_root = self.roots["checkout"]
        omitted = {
            source_root / ".git",
            source_root / "target",
            source_root / "dist/default/target",
        }
        for directory, directories, files in os.walk(source_root, followlinks=False):
            for name in directories + files:
                path = Path(directory) / name
                require(not path.is_symlink(), "candidate source contains symlinks")
            directories[:] = [
                name for name in directories if Path(directory) / name not in omitted
            ]
        require(
            not any(
                Path(config["docker"]).resolve().is_relative_to(self.roots[name])
                for name in ("checkout", "candidate")
            ),
            "Docker client is candidate writable",
        )
        for key, value in config["environment"].items():
            if key == "PATH":
                require(
                    all(Path(part).is_absolute() for part in value.split(":")),
                    "relative tool search path",
                )
                continue
            path = Path(value)
            require(
                path.is_absolute()
                and not path.is_relative_to("/tmp")
                and not any(
                    path.is_relative_to(self.roots[name])
                    for name in ("candidate", "checkout")
                ),
                "toolchain or Cargo seed path is candidate writable",
            )
        self.docker = [config["docker"], "--host", config["docker_host"]]
        self.client_home = self.control / "docker-client"
        self.client_home.mkdir(exist_ok=True, mode=0o700)
        self.client_env = {
            "PATH": os.defpath,
            "HOME": str(self.client_home),
            "DOCKER_CONFIG": str(self.client_home),
        }
        self.fixture_directory = self.control / "fixture-sockets"
        self.fixture_directory.mkdir(exist_ok=True, mode=0o755)
        self.fixture_map = self.control / "fixture-map.json"
        if not self.fixture_map.exists():
            self.fixture_map.write_bytes(b"[]\n")
        self.extra_readonly = []
        self.observations = []

    @classmethod
    def from_context(cls, path, expected):
        require(digest(path) == expected, "controller execution context digest differs")
        data = json.loads(Path(path).read_text())
        return cls(data["configuration"], data["roots"], data["control"])

    def write_context(self):
        path = self.control / "execution-context.json"
        path.write_bytes(
            canonical(
                {
                    "configuration": self.config,
                    "roots": {k: str(v) for k, v in self.roots.items()},
                    "control": str(self.control),
                }
            )
        )
        return path, digest(path)

    def _client(self, argv, **kwargs):
        kwargs.setdefault("timeout", 60)
        return subprocess.run([*self.docker, *argv], env=self.client_env, **kwargs)

    def sanitize_git(self):
        """Expose source history without GitLab clone credentials, hooks or host config."""
        source = self.roots["checkout"] / ".git"
        require(
            source.is_dir() and not source.is_symlink(),
            "CI checkout must have a regular Git directory",
        )
        require(
            not (source / "objects/info/alternates").exists(),
            "external Git object store",
        )
        destination = self.control / "candidate-git"
        if not destination.exists():
            destination.mkdir()
            for name in ("objects", "refs", "HEAD", "packed-refs", "shallow", "index"):
                path = source / name
                if not path.exists():
                    continue
                require(not path.is_symlink(), "indirect Git metadata")
                if path.is_dir():
                    require(
                        not any(p.is_symlink() for p in path.rglob("*")),
                        "indirect Git objects",
                    )
                    shutil.copytree(path, destination / name)
                else:
                    shutil.copyfile(path, destination / name)
            (destination / "config").write_text(
                "[core]\nrepositoryformatversion = 0\nbare = false\n"
            )
        return destination

    def environment(self, env):
        # An allowlist prevents ambient cloud/registry/SSH credentials crossing the boundary.
        allowed = {
            "CI",
            "LANG",
            "LC_ALL",
            "RUSTUP_TOOLCHAIN",
            "RUSTFLAGS",
            "RUSTDOCFLAGS",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_TARGET_DIR",
            "CARGO_BUILD_JOBS",
            "CARGO_TERM_COLOR",
            "CARGO_PROFILE_DEV_DEBUG",
            "CARGO_PROFILE_TEST_DEBUG",
            "CARGO_NET_GIT_FETCH_WITH_CLI",
            "TMPDIR",
            "MODERNCI_CACHE_DIR",
            "XDG_CACHE_HOME",
            "GIT_TERMINAL_PROMPT",
            "CI_SERVER_HOST",
            "CI_JOB_URL",
            "CI_JOB_ID",
            "CI_PIPELINE_ID",
            "VALKEY_URL",
            "BUSBAR_V4_TRANSPORT_URL",
            "BUSBAR_V4_TEST_TMP",
            "BUSBAR_VALKEY_SERVER",
            "BUSBAR_CHECKOUT",
            "BUSBAR_ADMISSION_CORE_REVISION",
            "BUSBAR_PIN",
            "BUSBAR_TEST_TMP_ROOT",
            "BUSBAR_TEST_VAULT_TOKEN",
            "BUSBAR_TEST_MYSQL_ROOT_PASSWORD",
            "BUSBAR_ARCHITECTURE_SOURCES",
            "BUSBAR_ARCHITECTURE_POLICY_SOURCES",
            "BUSBAR_ARCHITECTURE_GENERATED_DIRS",
        }
        from native_product_inputs import PATH_KEYS, SETTINGS

        allowed.update(
            PATH_KEYS
            | {
                SETTINGS,
                "BUSBAR_C_ABI_SOURCES",
                "BUSBAR_C_ABI_LIBRARY",
                "BUSBAR_PLUGIN_CDYLIB",
                "BUSBAR_BIN",
                "TSAN_OPTIONS",
            }
        )
        allowed.update(
            k
            for k in env
            if re.fullmatch(r"BUSBAR_TEST_[A-Z0-9_]+_(URL|ADDR|FIXTURE)", k)
        )
        result = {k: str(v) for k, v in env.items() if k in allowed}
        # Canonical source mappings contain no authentication headers or arbitrary Git options.
        count = int(env.get("GIT_CONFIG_COUNT", "0"))
        require(0 <= count <= 1000, "invalid Git mapping count")
        result["GIT_CONFIG_COUNT"] = str(count)
        for index in range(count):
            key, value = (
                env["GIT_CONFIG_KEY_" + str(index)],
                env["GIT_CONFIG_VALUE_" + str(index)],
            )
            prefix = (
                "url." + (self.roots["candidate"] / "canonical-inputs").as_uri() + "/"
            )
            require(
                key.startswith(prefix)
                and key.endswith(".insteadOf")
                and re.fullmatch(
                    r"https://github.com/GetBusbar/[a-zA-Z0-9_.-]+", value
                ),
                "unexpected Git setting in candidate environment",
            )
            result["GIT_CONFIG_KEY_" + str(index)] = key
            result["GIT_CONFIG_VALUE_" + str(index)] = value
        result.update(self.config["environment"])
        result.update(
            HOME=str(self.roots["candidate"] / "home"),
            GIT_CONFIG_GLOBAL="/dev/null",
            GIT_CONFIG_NOSYSTEM="1",
            CARGO_NET_OFFLINE="true",
            PYTHONDONTWRITEBYTECODE="1",
        )
        writable_directory(self.roots["candidate"], "home")
        return result

    def cargo_environment(self, argv, env):
        result = self.environment(env)
        if "--manifest-path" in argv:
            manifest = Path(argv[argv.index("--manifest-path") + 1]).resolve()
            if manifest.is_relative_to(self.roots["harness"]):
                # Stable since Cargo 1.97: trusted harness directories stay read-only.
                location = writable_directory(
                    self.roots["candidate"],
                    "harness-locks",
                    hashlib.sha256(str(manifest).encode()).hexdigest()
                    + "-"
                    + uuid.uuid4().hex,
                )
                lock = location / "Cargo.lock"
                require(not lock.is_symlink(), "indirect harness lockfile")
                original = manifest.parent / "Cargo.lock"
                if not lock.exists() and original.is_file():
                    shutil.copyfile(original, lock)
                require(not lock.is_symlink(), "indirect harness lockfile")
                result["CARGO_RESOLVER_LOCKFILE_PATH"] = str(lock)
                fresh = self.roots["candidate"] / ("harness-target-" + uuid.uuid4().hex)
                fresh.mkdir()
                result["CARGO_TARGET_DIR"] = str(fresh)
                result["RUSTFLAGS"] = ""
                result["RUSTDOCFLAGS"] = ""
                result["RUSTC_WRAPPER"] = ""
                result["RUSTC_WORKSPACE_WRAPPER"] = ""
        return result

    @contextmanager
    def invocation(self, argv, cwd, env):
        argv = list(map(str, argv))
        require(argv and not argv[0].startswith("-"), "missing candidate executable")
        cwd = Path(cwd).resolve()
        require(
            any(cwd.is_relative_to(root) for root in self.roots.values()),
            "candidate cwd escapes execution roots",
        )
        name = "busbar-candidate-" + uuid.uuid4().hex
        root = self.roots
        target = root["checkout"] / "target"
        target.mkdir(exist_ok=True)
        checked_directory(target)
        mounts = [
            (root["checkout"], root["checkout"], False),
            (root["candidate"], root["candidate"], True),
            (root["trusted"], root["trusted"], False),
            (root["harness"], root["harness"], False),
            (target, target, True),
            (self.sanitize_git(), root["checkout"] / ".git", False),
            (self.fixture_directory, Path("/__busbar_fixtures"), False),
            (self.fixture_map, Path("/__busbar_fixture_map.json"), False),
            (
                Path(__file__).with_name("confinement_entry.py"),
                Path("/__busbar_entry.py"),
                False,
            ),
        ]
        for relative in ("canonical-inputs", "host", "sdk", "c-witness"):
            path = root["candidate"] / relative
            if path.exists():
                mounts.append((checked_directory(path), path, False))
        nested_target = root["checkout"] / "dist/default/target"
        if nested_target.parent.is_dir():
            nested_target.mkdir(exist_ok=True)
            checked_directory(nested_target)
            mounts.append((nested_target, nested_target, True))
        mounts.extend(
            (checked_directory(path), Path(path), False) for path in self.extra_readonly
        )
        args = [
            "create",
            "--name",
            name,
            "--pull=never",
            "--read-only",
            "--network=none",
            "--runtime",
            self.config["runtime"],
            "--user",
            f"{self.config['uid']}:{self.config['gid']}",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--ipc=private",
            "--cgroupns=private",
            "--pids-limit=" + str(self.config["resources"]["pids"]),
            "--memory=" + str(self.config["resources"]["memory_bytes"]),
            "--cpus=" + str(self.config["resources"]["cpus"]),
            "--init",
            "--workdir",
            str(cwd),
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=1g,mode=1777",
            "--entrypoint",
            "/usr/bin/env",
        ]
        for source, destination, writable in mounts:
            require(
                "," not in str(source) and "," not in str(destination),
                "unsupported bind path",
            )
            args += [
                "--mount",
                f"type=bind,src={source},dst={destination}"
                + ("" if writable else ",readonly"),
            ]
        safe_env = self.cargo_environment(argv, env)
        args += [
            self.config["image"],
            "-i",
            *[key + "=" + value for key, value in sorted(safe_env.items())],
            self.config["python"],
            "-I",
            "-B",
            "/__busbar_entry.py",
            "--",
            *argv,
        ]
        observation = {
            "name": name,
            "image": self.config["image"],
            "runtime": self.config["runtime"],
            "candidate_uid": self.config["uid"],
            "disposed": False,
        }
        self.observations.append(observation)
        try:
            result = self._client(args, capture_output=True, text=True)
            require(result.returncode == 0, "candidate container creation failed")
            inspection = self._client(["inspect", name], capture_output=True, text=True)
            require(inspection.returncode == 0, "candidate inspection failed")
            actual = json.loads(inspection.stdout)[0]
            host = actual["HostConfig"]
            require(
                host["NetworkMode"] == "none"
                and host["ReadonlyRootfs"] is True
                and host["Privileged"] is False
                and host["PidMode"] in ("", "private")
                and host["IpcMode"] == "private"
                and host["CgroupnsMode"] == "private"
                and host["Runtime"] == self.config["runtime"]
                and actual["Config"]["User"]
                == f"{self.config['uid']}:{self.config['gid']}"
                and host["CapDrop"] == ["ALL"]
                and not host.get("CapAdd")
                and host["PidsLimit"] == self.config["resources"]["pids"]
                and host["Memory"] == self.config["resources"]["memory_bytes"]
                and host["NanoCpus"] == self.config["resources"]["cpus"] * 10**9
                and not host.get("Devices")
                and not host.get("DeviceRequests"),
                "runtime weakened candidate isolation",
            )
            expected_mounts = {(str(src), str(dst), rw) for src, dst, rw in mounts}
            actual_mounts = {
                (m["Source"], m["Destination"], m["RW"])
                for m in actual["Mounts"]
                if m["Type"] == "bind"
            }
            require(
                all(m["Type"] in ("bind", "tmpfs") for m in actual["Mounts"]),
                "unexpected image volume",
            )
            require(actual_mounts == expected_mounts, "runtime candidate mounts differ")
            require(
                any(
                    value in ("no-new-privileges", "no-new-privileges:true")
                    for value in host["SecurityOpt"]
                ),
                "runtime permits privilege gain",
            )
            observation.update(
                container_id=actual["Id"],
                image_id=actual["Image"],
                network="none",
                inspected=True,
            )
            yield [
                *self.docker,
                "start",
                "--attach",
                name,
            ], self.client_env, observation
        finally:
            result = self._client(
                ["rm", "--force", name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            absent = self._client(
                [
                    "container",
                    "ls",
                    "--all",
                    "--quiet",
                    "--filter",
                    "name=^/" + name + "$",
                ],
                capture_output=True,
                text=True,
            )
            require(
                absent.returncode == 0
                and not absent.stdout.strip()
                and (result.returncode == 0 or not observation.get("inspected")),
                "candidate disposal was not confirmed",
            )
            observation["disposed"] = True

    def run(self, argv, *, cwd, env=None, **kwargs):
        with self.invocation(argv, cwd, os.environ if env is None else env) as (
            command,
            client_env,
            _,
        ):
            return subprocess.run(command, env=client_env, **kwargs)

    def check_output(self, argv, *, cwd, env=None, **kwargs):
        with self.invocation(argv, cwd, os.environ if env is None else env) as (
            command,
            client_env,
            _,
        ):
            return subprocess.check_output(command, env=client_env, **kwargs)
