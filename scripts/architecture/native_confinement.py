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
import stat
import subprocess
import uuid

import linux_job_isolation


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
                "isolation",
                "collector",
            },
            "unknown isolation configuration",
        )
        require(
            config["schema"] == "busbar.native-confinement/2",
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
            re.fullmatch(r"(?:[a-z0-9./:_-]+@)?sha256:[0-9a-f]{64}", config["image"]),
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
        linux_job_isolation.validate_configuration(config["isolation"])
        collector = config['collector']
        require(isinstance(collector, dict) and set(collector) in ({'docker_host', 'uid', 'gid'}, {'docker_host', 'uid', 'gid', 'image'})
                and re.fullmatch(r'(?:[a-z0-9./:_-]+@)?sha256:[0-9a-f]{64}', collector.get('image', config['image']))
                and re.fullmatch(r'unix:///[^\s,]+', collector['docker_host'])
                and collector['uid'] == config['isolation']['uid_map'][1] + config['uid']
                and collector['gid'] == config['isolation']['gid_map'][1] + config['gid'],
                'invalid protected dependency collector identity')
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
                    all(Path(part).is_absolute()
                        and not Path(part).is_relative_to('/tmp')
                        and not any(Path(part).is_relative_to(self.roots[name])
                                    for name in ('candidate', 'checkout'))
                        for part in value.split(":")),
                    "relative or candidate writable tool search path",
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
        self.product_inputs = {}
        self.oracle_inputs = {}
        self.conformance_capabilities = None
        self.conformance_mounts = []
        self.conformance_inputs_manifest = None
        self.dependency_seed = None
        self.dependency_seed_sha256 = None

    @classmethod
    def from_context(cls, path, expected):
        require(digest(path) == expected, "controller execution context digest differs")
        data = json.loads(Path(path).read_text())
        execution = cls(data["configuration"], data["roots"], data["control"])
        execution.extra_readonly = [checked_directory(value) for value in data.get('extra_readonly', [])]
        execution.conformance_mounts = [(Path(source), Path(target)) for source, target in data.get('conformance_mounts', [])]
        if data.get('conformance_inputs_manifest'):
            execution.conformance_inputs_manifest = Path(data['conformance_inputs_manifest'])
        if data.get('dependency_seed') is not None:
            execution.dependency_seed = checked_directory(data['dependency_seed'])
            execution.dependency_seed_sha256 = data['dependency_seed_sha256']
        return execution

    def write_context(self):
        path = self.control / "execution-context.json"
        path.write_bytes(
            canonical(
                {
                    "configuration": self.config,
                    "roots": {k: str(v) for k, v in self.roots.items()},
                    "control": str(self.control),
                    "extra_readonly": list(map(str, self.extra_readonly)),
                    "conformance_mounts": [[str(source), str(target)] for source, target in self.conformance_mounts],
                    "conformance_inputs_manifest": str(self.conformance_inputs_manifest) if self.conformance_inputs_manifest else None,
                    "dependency_seed": str(self.dependency_seed) if self.dependency_seed else None,
                    "dependency_seed_sha256": self.dependency_seed_sha256,
                }
            )
        )
        return path, digest(path)

    def _client(self, argv, **kwargs):
        kwargs.setdefault("timeout", 60)
        return subprocess.run([*self.docker, *argv], env=self.client_env, **kwargs)

    def collector_client(self, argv, **kwargs):
        """Only trusted fetch code uses the separate pre-existing network daemon."""
        kwargs.setdefault("timeout", 60)
        command = [self.config['docker'], '--host', self.config['collector']['docker_host'], *argv]
        return subprocess.run(command, env=self.client_env, **kwargs)

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

    def allow_product_inputs(self, values):
        from native_product_inputs import ProductInputs

        require(isinstance(values, ProductInputs), "product inputs require controller validation")
        self.product_inputs = dict(values)

    def allow_oracle_inputs(self, values):
        from native_oracle import OracleInputs
        require(isinstance(values, OracleInputs), 'oracle inputs require signed controller validation')
        self.oracle_inputs = dict(values)

    def register_generated(self, path):
        root = checked_directory(path)
        require(root.is_relative_to(self.roots['candidate'] / 'generated'),
                'generated project escapes its registered output root')
        total = 0
        for entry in root.rglob('*'):
            info = entry.lstat()
            require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),
                    'generated project contains indirect or special files')
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
                require(info.st_nlink == 1 and info.st_size <= 16 * 1024**2 and total <= 128 * 1024**2,
                        'generated source exceeds its collection bounds')
            require('.git' not in entry.relative_to(root).parts,
                    'generated projects must not supply Git control metadata')
        self.extra_readonly.append(root)

    def set_conformance_capabilities(self, manifest, repository, source, expected=None):
        """Only a protected controller input can authorize pre-staged suite interfaces."""
        if manifest is None:
            data = {'schema': 'busbar.conformance.capabilities/1', 'repo': repository,
                    'source': source, 'toolchain_ready': False, 'suites': {}}
        else:
            manifest = Path(manifest)
            require(expected and digest(manifest) == expected,
                    'protected conformance capabilities digest differs')
            require(not manifest.is_symlink() and not any(
                manifest.resolve().is_relative_to(self.roots[key])
                for key in ('checkout', 'candidate')), 'candidate supplied conformance capabilities')
            data = json.loads(manifest.read_text())
        require(set(data) == {'schema', 'repo', 'source', 'toolchain_ready', 'suites'}
                and data['schema'] == 'busbar.conformance.capabilities/1'
                and data['repo'] == repository and data['source'] == source
                and type(data['toolchain_ready']) is bool and isinstance(data['suites'], dict),
                'conformance capability identity or schema differs')
        for name, row in data['suites'].items():
            require(re.fullmatch(r'[a-z0-9][a-z0-9-]*', name)
                    and isinstance(row, dict) and set(row) <= {'available', 'reason'}
                    and type(row.get('available')) is bool
                    and isinstance(row.get('reason', ''), str)
                    and len(row.get('reason', '')) <= 2000,
                    'invalid conformance suite capability')
        path = self.control / 'conformance-capabilities.json'
        path.write_bytes(canonical(data))
        path.chmod(0o444)
        self.conformance_capabilities = path
        return digest(path)

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
            "CI_PROJECT_PATH",
            "CONFORMANCE_OUT",
            "CONFORMANCE_TIMEOUT_SECONDS",
            "VALKEY_URL",
            "BUSBAR_V4_TRANSPORT_URL",
            "BUSBAR_V4_TEST_TMP",
            "BUSBAR_VALKEY_SERVER",
            "BUSBAR_CHECKOUT",
            "BUSBAR_ADMISSION_CORE_REVISION",
            "BUSBAR_SDK_CHECKOUT",
            "BUSBAR_SDK_REVISION",
            "BUSBAR_SCAFFOLD_OUTPUT",
            "BUSBAR_PIN",
            "BUSBAR_TEST_TMP_ROOT",
            "BUSBAR_TEST_VAULT_TOKEN",
            "BUSBAR_TEST_MYSQL_ROOT_PASSWORD",
            "BUSBAR_ARCHITECTURE_SOURCES",
            "BUSBAR_ARCHITECTURE_POLICY_SOURCES",
            "BUSBAR_ARCHITECTURE_GENERATED_DIRS",
        }
        allowed.update(
            {
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
        for key, value in (self.product_inputs | self.oracle_inputs).items():
            if key in env:
                require(env[key] == value, "registered product input was overridden")
                result[key] = value
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
        # Git rejects these controller-owned repositories under the remapped UID.
        # Trust only exact, read-only source mounts chosen here, never an ambient
        # safe.directory value or a wildcard supplied by candidate code.
        git_roots = [self.roots['checkout'], self.roots['trusted']]
        for relative in ('host', 'sdk', 'c-witness'):
            path = self.roots['candidate'] / relative
            if path.exists():
                git_roots.append(checked_directory(path))
        for path in git_roots:
            result['GIT_CONFIG_KEY_' + str(count)] = 'safe.directory'
            result['GIT_CONFIG_VALUE_' + str(count)] = str(path)
            count += 1
        result['GIT_CONFIG_COUNT'] = str(count)
        result.update(self.config["environment"])
        if self.conformance_inputs_manifest is not None:
            result['BUSBAR_CONFORMANCE_INPUTS'] = '/__busbar_conformance_inputs.json'
        if self.dependency_seed is not None:
            result['CARGO_HOME'] = '/__busbar_job_seed'
        if self.conformance_capabilities is not None:
            result['CONFORMANCE_CAPABILITIES'] = '/__busbar_conformance_capabilities.json'
            capability_identity = json.loads(self.conformance_capabilities.read_text())
            result['MODERNCI_REPO'] = capability_identity['repo']
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

    def prepare_command(self, argv, cwd):
        if argv[:2] != ['cargo', 'vet']:
            return argv
        require('--store-path' not in argv, 'candidate-selected vet store is forbidden')
        manifest = Path(cwd) / 'Cargo.toml'
        if '--manifest-path' in argv:
            manifest = Path(argv[argv.index('--manifest-path') + 1])
            if not manifest.is_absolute():
                manifest = Path(cwd) / manifest
        store = manifest.parent / 'supply-chain'
        require(store.is_dir() and not any(p.is_symlink() for p in (store, *store.rglob('*'))),
                'missing or indirect vet policy store')
        # cargo-vet takes writable locks even with --locked/--frozen. Give it a
        # fresh copy, retaining the source policy and earlier invocation isolation.
        destination = self.roots['candidate'] / ('vet-store-' + uuid.uuid4().hex)
        shutil.copytree(store, destination)
        return [*argv, '--store-path', str(destination)]

    @contextmanager
    def invocation(self, argv, cwd, env, *, discard_harness_target=False):
        argv = list(map(str, argv))
        require(argv and not argv[0].startswith("-"), "missing candidate executable")
        if discard_harness_target:
            require(argv[0] == 'cargo' and '--manifest-path' in argv
                    and argv.index('--manifest-path') + 1 < len(argv)
                    and Path(argv[argv.index('--manifest-path') + 1]).resolve().is_relative_to(
                        self.roots['harness']),
                    'disposable target requires a trusted harness manifest')
        cwd = Path(cwd).resolve()
        require(
            any(cwd.is_relative_to(root) for root in self.roots.values()),
            "candidate cwd escapes execution roots",
        )
        argv = self.prepare_command(argv, cwd)
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
        mounts.extend((source, target, False) for source, target in self.conformance_mounts)
        if self.conformance_capabilities is not None:
            mounts.append((self.conformance_capabilities,
                           Path('/__busbar_conformance_capabilities.json'), False))
        if self.dependency_seed is not None:
            mounts.append((self.dependency_seed, Path('/__busbar_job_seed'), False))
        fixture_hosts = (['localhost.emobix.co.uk:127.0.0.1', 'busbar.oidf.test:127.0.0.1']
                         if any(target == Path('/opt/busbar-conformance/oidf')
                                for _, target in self.conformance_mounts) else [])
        if any(target == Path('/opt/busbar-conformance/a2a-tools')
               for _, target in self.conformance_mounts):
            # The pinned TCK uses example.com for push-config CRUD, not delivery.
            # Freeze its public DNS answers observed 2026-11-11 for the offline
            # destination judge; network=none still prevents external delivery.
            fixture_hosts += ['example.com:104.20.23.154', 'example.com:172.66.147.243']
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
            "--memory-swap=" + str(self.config["resources"]["memory_bytes"]),
            "--cpus=" + str(self.config["resources"]["cpus"]),
            "--init",
            "--workdir",
            str(cwd),
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=1g,nr_inodes=65536,mode=1777",
            "--shm-size=64m",
            "--entrypoint",
            "/usr/bin/env",
        ]
        for alias in fixture_hosts:
            args += ['--add-host', alias]
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
        disposable_target = None
        if discard_harness_target:
            disposable_target = Path(safe_env['CARGO_TARGET_DIR'])
            require(disposable_target.parent == root['candidate']
                    and re.fullmatch(r'harness-target-[0-9a-f]{32}', disposable_target.name)
                    and not disposable_target.is_symlink(),
                    'invalid disposable harness target')
        cargo_home = None
        if safe_env.get('CARGO_HOME'):
            # Stable dependency paths preserve Cargo target fingerprints. The
            # contents remain fresh for every invocation and are removed below.
            cargo_home = root['candidate'] / 'cargo-home-invocation'
            cargo_home.mkdir(mode=0o700)
            safe_env['BUSBAR_INVOCATION_CARGO_HOME'] = str(cargo_home)
        isolation = self.config['isolation']
        storage = linux_job_isolation.prepare_writable(isolation, [src for src, _, writable in mounts if writable],
                                   self.config['uid'], self.config['gid'])
        daemon_result = self._client(['info', '--format', '{{json .}}'], capture_output=True, text=True)
        require(daemon_result.returncode == 0, 'candidate daemon identity unavailable')
        daemon = json.loads(daemon_result.stdout)
        user_namespace = linux_job_isolation.validate_userns(isolation, daemon)
        safe_env.update(BUSBAR_EXPECTED_UID_MAP=json.dumps(isolation['uid_map']),
                        BUSBAR_EXPECTED_GID_MAP=json.dumps(isolation['gid_map']))
        storage.update(tmp_bytes=1024**3, tmp_inodes=65536, shm_bytes=64 * 1024**2)
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
            "command_sha256": hashlib.sha256(canonical(argv)).hexdigest(),
            "environment_sha256": hashlib.sha256(canonical(safe_env)).hexdigest(),
            "working_directory": str(cwd),
            "docker_client_sha256": self.config['docker_sha256'],
            "configuration_sha256": hashlib.sha256(canonical(self.config)).hexdigest(),
            "resources": dict(self.config['resources']),
            "dependency_seed_sha256": self.dependency_seed_sha256,
            "storage": storage,
            "user_namespace": user_namespace,
            "fixture_hosts": fixture_hosts,
        }
        self.observations.append(observation)
        try:
            result = self._client(args, capture_output=True, text=True)
            require(result.returncode == 0, "candidate container creation failed")
            inspection = self._client(["inspect", name], capture_output=True, text=True)
            require(inspection.returncode == 0, "candidate inspection failed")
            actual = json.loads(inspection.stdout)[0]
            linux_job_isolation.validate_userns(isolation, daemon, actual)
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
                and not host.get("DeviceRequests")
                and (host.get('ExtraHosts') or []) == fixture_hosts
                and host.get('ShmSize') == 64 * 1024**2
                and host.get('Tmpfs') == {'/tmp': 'rw,nosuid,nodev,size=1g,nr_inodes=65536,mode=1777'},
                "runtime weakened candidate isolation",
            )
            swap_bound = linux_job_isolation.validate_swap_bound(
                daemon, host, self.config['resources']['memory_bytes'])
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
                mounts_sha256=hashlib.sha256(canonical(sorted(expected_mounts))).hexdigest(),
                security_options=host['SecurityOpt'],
                swap_bound=swap_bound,
            )
            yield [
                *self.docker,
                "start",
                "--attach",
                name,
            ], self.client_env, observation
        finally:
            # Read process state from the engine before deleting the container.
            # These controller observations are still not an independent host attestation.
            state_error = None
            if observation.get('inspected'):
                try:
                    state = self._client(['inspect', '--format', '{{json .State}}', name],
                                         capture_output=True, text=True)
                    require(state.returncode == 0, 'candidate process state unavailable')
                    actual_state = json.loads(state.stdout)
                    observation['state_before_disposal'] = {
                        key: actual_state.get(key) for key in
                        ('Status', 'Running', 'ExitCode', 'OOMKilled', 'Error', 'StartedAt', 'FinishedAt')}
                except Exception as error:
                    state_error = error
                    observation['state_observation_error'] = type(error).__name__
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
            if disposable_target is not None:
                # The container is gone before touching candidate-owned artifacts.
                # Unlink a replaced top-level symlink instead of following it;
                # rmtree likewise does not follow links inside the original target.
                if disposable_target.is_symlink():
                    disposable_target.unlink()
                elif disposable_target.exists():
                    shutil.rmtree(disposable_target)
                observation['harness_target_removed'] = True
                observation['harness_target_path_sha256'] = hashlib.sha256(
                    str(disposable_target).encode()).hexdigest()
            if cargo_home is not None:
                if cargo_home.is_symlink():
                    cargo_home.unlink()
                elif cargo_home.exists():
                    shutil.rmtree(cargo_home)
                observation['private_cargo_cache_removed'] = True
            if 'swap_bound' in observation:
                linux_job_isolation.recheck_swap_bound(observation['swap_bound'])
            require(state_error is None, 'candidate process state observation failed')

    def run(self, argv, *, cwd, env=None, discard_harness_target=False, **kwargs):
        with self.invocation(argv, cwd, os.environ if env is None else env,
                             discard_harness_target=discard_harness_target) as (
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
