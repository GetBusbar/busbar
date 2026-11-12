"""Direct confinement regressions; optional real existing-runtime witnesses.

Set BUSBAR_CONFINEMENT_TEST_CONFIG to a protected local test configuration to
exercise Docker. Tests never pull an image, install a runtime or alter CI settings.
"""

import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import check
from confinement_entry import ignore_cargo_seed_entries
import linux_job_isolation
import native
from native_confinement import Execution, digest
from native_fixture_proxy import Fixtures


class Fixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.roots = {
            key: self.base / key
            for key in ("checkout", "candidate", "trusted", "harness")
        }
        self.control = self.base / "control"
        for path in [*self.roots.values(), self.control]:
            path.mkdir()
        (self.roots["checkout"] / ".git").mkdir()
        (self.roots["checkout"] / ".git/config").write_text(
            "url=https://secret-token@example.invalid/repo"
        )
        self.config = {
            "schema": "busbar.native-confinement/2",
            "docker": "/bin/echo",
            "docker_sha256": digest("/bin/echo"),
            "docker_host": "unix:///var/run/docker.sock",
            "image": "python@sha256:" + "a" * 64,
            "runtime": "runc",
            "uid": 1000,
            "gid": 1000,
            "python": "/usr/local/bin/python3",
            "environment": {"PATH": "/usr/local/bin:/usr/bin:/bin"},
            "resources": {"cpus": 2, "memory_bytes": 2 * 1024**3, "pids": 256},
            "collector": {"docker_host": "unix:///var/run/docker.sock", "uid": 525288, "gid": 525288},
            "isolation": {
                "storage_kind": "tmpfs",
                "storage_reserve_bytes": 0,
                "storage_root": str(self.base),
                "storage_bytes": 64 * 1024**2,
                "storage_inodes": 4096,
                "uid_map": [0, 524288, 65536],
                "gid_map": [0, 524288, 65536],
            },
        }

    def execution(self):
        return Execution(self.config, self.roots, self.control)


class Boundary(Fixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        # Host-kernel contracts have separate focused tests and actual Linux
        # witnesses. Only these controller unit tests substitute them.
        for name in ("prepare_writable", "validate_userns", "validate_storage"):
            mocked = patch.object(linux_job_isolation, name, return_value={})
            mocked.start()
            self.addCleanup(mocked.stop)

    def test_private_cargo_seed_keeps_nested_registry_bin_sources(self):
        seed = self.base / "cargo-seed"
        root_bin = seed / "bin"
        marker = seed / ".package-cache"
        nested_bin = (
            seed / "registry/src/index.crates.io-abc/tikv-jemalloc-sys/jemalloc/bin"
        )
        root_bin.mkdir(parents=True)
        nested_bin.mkdir(parents=True)
        (root_bin / "cargo-subcommand").write_text("image-owned tool")
        marker.write_text("image cache marker")
        source = nested_bin / "jemalloc-config.in"
        source.write_text("registry package source")
        copied = self.base / "cargo-home-invocation"

        import shutil

        shutil.copytree(
            seed,
            copied,
            ignore=lambda directory, names: ignore_cargo_seed_entries(
                seed, directory, names
            ),
        )

        self.assertFalse((copied / "bin").exists())
        self.assertFalse((copied / ".package-cache").exists())
        self.assertEqual(
            (copied / source.relative_to(seed)).read_text(), "registry package source"
        )

    def test_requires_pinned_client_image_nonroot_and_private_roots(self):
        for key, value in [
            ("docker_sha256", "0" * 64),
            ("image", "python:latest"),
            ("uid", 0),
            ("runtime", "untrusted"),
            ("docker_host", "tcp://host:2375"),
        ]:
            with self.subTest(key=key):
                config = dict(self.config, **{key: value})
                with self.assertRaises(ValueError):
                    Execution(config, self.roots, self.control)
        with self.assertRaises(ValueError):
            Execution(
                self.config,
                dict(self.roots, harness=self.roots["candidate"]),
                self.control,
            )
        (self.roots["checkout"] / "indirect").symlink_to(self.control)
        with self.assertRaisesRegex(ValueError, "symlinks"):
            self.execution()

    def test_local_loaded_image_ids_remain_immutable_and_collector_specific(self):
        self.config['image'] = 'sha256:' + 'a' * 64
        self.config['collector']['image'] = 'sha256:' + 'b' * 64
        self.execution()
        self.config['collector']['image'] = 'python:latest'
        with self.assertRaisesRegex(ValueError, 'collector'):
            self.execution()

    def test_context_is_digest_bound_and_git_credentials_are_absent(self):
        execution = self.execution()
        path, expected = execution.write_context()
        self.assertEqual(Execution.from_context(path, expected).roots, execution.roots)
        path.write_text(path.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "digest"):
            Execution.from_context(path, expected)
        safe = execution.sanitize_git()
        self.assertNotIn("secret-token", (safe / "config").read_text())
        (self.roots["checkout"] / ".git/objects/info").mkdir(parents=True)
        (self.roots["checkout"] / ".git/objects/info/alternates").write_text(
            "/host/private"
        )
        with self.assertRaisesRegex(ValueError, "external Git"):
            execution.sanitize_git()

    def test_environment_is_allowlisted_and_git_auth_cannot_cross(self):
        execution = self.execution()
        result = execution.environment(
            {
                "CI_JOB_TOKEN": "secret",
                "AWS_ACCESS_KEY_ID": "secret",
                "GOOGLE_APPLICATION_CREDENTIALS": "/host/key",
                "UNKNOWN_SECRET": "secret",
                "BUSBAR_TEST_VAULT_TOKEN": "fixture",
                "CARGO_TARGET_DIR": str(self.roots["candidate"] / "target"),
            }
        )
        self.assertFalse(any("secret" in str(v) for v in result.values()))
        self.assertEqual(result["BUSBAR_TEST_VAULT_TOKEN"], "fixture")
        with self.assertRaisesRegex(ValueError, "Git setting"):
            execution.environment(
                {
                    "GIT_CONFIG_COUNT": "1",
                    "GIT_CONFIG_KEY_0": "http.extraheader",
                    "GIT_CONFIG_VALUE_0": "Authorization: secret",
                }
            )

    def test_git_ownership_exceptions_are_exact_controller_mounts(self):
        execution = self.execution()
        host = self.roots['candidate'] / 'host'
        host.mkdir()
        result = execution.environment({})
        settings = [(result['GIT_CONFIG_KEY_' + str(index)],
                     result['GIT_CONFIG_VALUE_' + str(index)])
                    for index in range(int(result['GIT_CONFIG_COUNT']))]
        self.assertEqual(settings, [('safe.directory', str(path)) for path in
                                    (self.roots['checkout'], self.roots['trusted'], host)])
        self.assertEqual(result['GIT_CONFIG_GLOBAL'], '/dev/null')
        self.assertEqual(result['GIT_CONFIG_NOSYSTEM'], '1')
        for value in ('*', str(self.control), str(self.roots['candidate'])):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'Git setting'):
                execution.environment({'GIT_CONFIG_COUNT': '1',
                    'GIT_CONFIG_KEY_0': 'safe.directory', 'GIT_CONFIG_VALUE_0': value})

    def test_git_reads_registered_root_but_rejects_other_owner_repository(self):
        execution = self.execution()
        other = self.base / 'unregistered'
        other.mkdir()
        for path in (self.roots['trusted'], other):
            subprocess.run(['git', 'init', '-q', str(path)], check=True)
        env = execution.environment({})
        # Git's own deterministic ownership witness exercises the real safe.directory
        # handling without changing host users or relying on shared-filesystem chown.
        env['GIT_TEST_ASSUME_DIFFERENT_OWNER'] = 'true'
        for path, permitted in ((self.roots['trusted'], True), (other, False)):
            result = subprocess.run(['git', '-C', str(path), 'rev-parse', '--show-toplevel'],
                                    env=env, capture_output=True, text=True)
            if permitted:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(Path(result.stdout.strip()), path)
            else:
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('dubious ownership', result.stderr)

    def test_product_bindings_require_explicit_validation_and_cannot_be_overridden(self):
        from native_product_inputs import ProductInputs

        execution = self.execution()
        key = "BUSBAR_TEST_FIXTURE_CDYLIB"
        value = str(self.roots["candidate"] / "target/fixture.so")
        self.assertNotIn(key, execution.environment({key: value}))
        with self.assertRaisesRegex(ValueError, "controller validation"):
            execution.allow_product_inputs({key: value})
        execution.allow_product_inputs(ProductInputs({key: value}))
        self.assertEqual(execution.environment({key: value})[key], value)
        with self.assertRaisesRegex(ValueError, "overridden"):
            execution.environment({key: "/host/other.so"})
        self.assertNotIn("BUSBAR_TEST_UNKNOWN_CDYLIB", execution.environment({
            key: value, "BUSBAR_TEST_UNKNOWN_CDYLIB": value}))

    def test_conformance_manifest_is_controller_pinned_and_not_environment_authorized(self):
        execution = self.execution()
        self.assertNotIn('CONFORMANCE_CAPABILITIES', execution.environment({
            'CONFORMANCE_CAPABILITIES': '/candidate/forged.json'}))
        source = 'a' * 40
        data = {'schema': 'busbar.conformance.capabilities/1', 'repo': 'GetBusbar/busbar',
                'source': source, 'toolchain_ready': True,
                'suites': {'h2': {'available': False, 'reason': 'fixture not staged'}}}
        path = self.control / 'approved-capabilities.json'
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'digest differs'):
            execution.set_conformance_capabilities(path, data['repo'], source, '0' * 64)
        with self.assertRaisesRegex(ValueError, 'identity'):
            execution.set_conformance_capabilities(path, data['repo'], 'b' * 40, digest(path))
        execution.set_conformance_capabilities(path, data['repo'], source, digest(path))
        self.assertEqual(execution.environment({'CONFORMANCE_CAPABILITIES': 'forged'})[
            'CONFORMANCE_CAPABILITIES'], '/__busbar_conformance_capabilities.json')
        self.assertEqual(json.loads(execution.conformance_capabilities.read_text()), data)
        self.assertEqual(execution.conformance_capabilities.stat().st_mode & 0o222, 0)

    def test_weakened_runtime_refuses_and_daemon_loss_is_not_disposal_proof(self):
        for daemon_available in (True, False):
            execution = self.execution()
            calls = []

            def client(argv, **kwargs):
                calls.append(argv[0])
                payload = (
                    json.dumps([{"HostConfig": {"NetworkMode": "bridge"}}])
                    if argv[0] == "inspect"
                    else json.dumps({"SecurityOptions": ["name=userns"]})
                    if argv[0] == "info" else ""
                )
                code = 1 if argv[0] == "container" and not daemon_available else 0
                return subprocess.CompletedProcess(
                    argv, code, stdout=payload, stderr=""
                )

            with patch.object(execution, "_client", side_effect=client):
                with self.assertRaisesRegex(
                    ValueError, "weakened" if daemon_available else "disposal"
                ):
                    with execution.invocation(
                        ["python3", "-c", "print(1)"], self.roots["checkout"], {}
                    ):
                        self.fail("weakened runtime was executed")
            self.assertNotIn("start", calls)
            self.assertEqual(execution.observations[-1]["disposed"], daemon_available)

    def test_private_cargo_cache_resets_at_stable_dependency_path(self):
        self.config['environment']['CARGO_HOME'] = '/opt/seed'
        execution = self.execution()
        paths = []
        def client(argv, **kwargs):
            if argv[0] == 'create':
                paths.extend(value.split('=', 1)[1] for value in argv
                             if value.startswith('BUSBAR_INVOCATION_CARGO_HOME='))
            payload = (json.dumps([{'HostConfig': {'NetworkMode': 'bridge'}}]) if argv[0] == 'inspect'
                       else json.dumps({'SecurityOptions': ['name=userns']}) if argv[0] == 'info' else '')
            return subprocess.CompletedProcess(argv, 0, stdout=payload, stderr='')
        with patch.object(execution, '_client', side_effect=client):
            for _ in range(2):
                with self.assertRaisesRegex(ValueError, 'weakened'):
                    with execution.invocation(['python3', '-c', 'pass'], self.roots['checkout'], {}):
                        self.fail('weakened runtime executed')
                self.assertFalse((self.roots['candidate'] / 'cargo-home-invocation').exists())
        self.assertEqual(paths, [str(self.roots['candidate'] / 'cargo-home-invocation')] * 2)

    def test_empty_cargo_home_only_for_vendored_harness_checks(self):
        self.config['environment']['CARGO_HOME'] = '/opt/seed'
        execution = self.execution()
        manifest = self.roots["harness"] / "Cargo.toml"
        manifest.write_text("[workspace]\n")
        vendored = ['cargo', 'check', '--manifest-path', str(manifest), '--config', '/v.toml']
        for argv, discard in ((vendored, False), (vendored[:4], True),
                              (['cargo', 'build', *vendored[2:]], True)):
            with self.subTest(argv=argv, discard=discard):
                with self.assertRaisesRegex(ValueError, 'vendored harness compiler check'):
                    with execution.invocation(argv, self.roots['checkout'], {},
                                              discard_harness_target=discard, vendored_sources=True):
                        self.fail('unvendored command skipped the seed copy')
        flags = []
        def client(argv, **kwargs):
            if argv[0] == 'create':
                flags.append([value for value in argv if value.startswith('BUSBAR_INVOCATION_CARGO_HOME_EMPTY=')])
            payload = (json.dumps([{'HostConfig': {'NetworkMode': 'bridge'}}]) if argv[0] == 'inspect'
                       else json.dumps({'SecurityOptions': ['name=userns']}) if argv[0] == 'info' else '')
            return subprocess.CompletedProcess(argv, 0, stdout=payload, stderr='')
        with patch.object(execution, '_client', side_effect=client):
            for flag in (True, False):
                with self.assertRaisesRegex(ValueError, 'weakened'):
                    with execution.invocation(vendored, self.roots['checkout'], {},
                                              discard_harness_target=True, vendored_sources=flag):
                        self.fail('weakened runtime executed')
        self.assertEqual(flags, [['BUSBAR_INVOCATION_CARGO_HOME_EMPTY=1'], []])

    def test_harness_lock_and_artifacts_are_separate_from_readonly_sources(self):
        execution = self.execution()
        manifest = self.roots["harness"] / "Cargo.toml"
        manifest.write_text("[workspace]\n")
        first = execution.cargo_environment(
            ["cargo", "check", "--manifest-path", str(manifest)], {}
        )
        second = execution.cargo_environment(
            ["cargo", "check", "--manifest-path", str(manifest)], {}
        )
        self.assertNotEqual(first["CARGO_TARGET_DIR"], second["CARGO_TARGET_DIR"])
        self.assertTrue(
            Path(first["CARGO_RESOLVER_LOCKFILE_PATH"]).is_relative_to(
                self.roots["candidate"]
            )
        )
        self.assertFalse((self.roots["harness"] / "Cargo.lock").exists())

    def test_candidate_symlinks_cannot_redirect_controller_harness_preparation(self):
        execution = self.execution()
        manifest = self.roots["harness"] / "Cargo.toml"
        manifest.write_text("[workspace]\n")
        (self.roots["candidate"] / "harness-locks").symlink_to(
            self.control, target_is_directory=True
        )
        before = set(self.control.iterdir())
        with self.assertRaisesRegex(ValueError, "indirect writable"):
            execution.cargo_environment(
                ["cargo", "check", "--manifest-path", str(manifest)], {}
            )
        self.assertEqual(set(self.control.iterdir()), before)

    def test_architecture_compiler_calls_have_no_host_fallback(self):
        execution = self.execution()
        with patch.object(check, "EXECUTION", execution), patch.object(
            execution, "run", side_effect=ValueError("unavailable")
        ), patch.object(check.subprocess, "run") as host:
            with self.assertRaisesRegex(ValueError, "unavailable"):
                check.candidate_run(["cargo", "check"])
            host.assert_not_called()

    def test_conformance_without_migrated_fixture_api_refuses(self):
        q = native.Qualification.__new__(native.Qualification)
        q.execution = self.execution()
        q.root = self.roots["checkout"]
        with self.assertRaisesRegex(native.Violation, "controller-owned"):
            q.conformance("confined")
        with self.assertRaisesRegex(native.Violation, "fixed-destination"):
            q.external_endpoint_conformance()

    def test_artifact_intake_rejects_symlinks_fifos_and_oversized_files(self):
        q = SimpleNamespace(work=self.roots["candidate"], root=self.roots["checkout"])
        source, destination = q.work / "artifact", self.control / "artifact"
        source.write_bytes(b"actual artifact")
        native.collect_output(q, source, destination)
        self.assertEqual(destination.read_bytes(), b"actual artifact")
        destination.unlink()
        with self.assertRaisesRegex(native.Violation, "exceeds limit"):
            native.collect_output(q, source, destination, limit=1)
        source.unlink()
        source.symlink_to(self.control / "secret")
        with self.assertRaisesRegex(native.Violation, "indirect"):
            native.collect_output(q, source, destination)
        source.unlink()
        os.mkfifo(source)
        with self.assertRaisesRegex(native.Violation, "nonregular"):
            native.collect_output(q, source, destination)

    def test_artifact_intake_rejects_parent_traversal_and_hardlinks(self):
        q = SimpleNamespace(work=self.roots["candidate"], root=self.roots["checkout"])
        secret = self.control / "secret"
        secret.write_bytes(b"controller only")
        destination = self.control / "artifact"
        with self.assertRaisesRegex(native.Violation, "escapes"):
            native.collect_output(q, q.work / "../control/secret", destination)
        alias = q.work / "linked"
        os.link(secret, alias)
        with self.assertRaisesRegex(native.Violation, "linked"):
            native.collect_output(q, alias, destination)
        self.assertFalse(destination.exists())

    def test_cargo_hardlinked_output_is_copied_to_single_link_controller_artifact(self):
        q = SimpleNamespace(work=self.roots['candidate'], root=self.roots['checkout'], receipt={})
        original = q.work / 'compiler.so'
        original.write_bytes(b'actual compiler fixture content')
        alias = q.work / 'compiler-alias.so'
        os.link(original, alias)
        destination = self.control / 'artifact.so'
        native.collect_output(q, alias, destination, compiler_output=True)
        self.assertEqual(destination.read_bytes(), original.read_bytes())
        self.assertEqual(destination.stat().st_nlink, 1)
        self.assertEqual(q.receipt['collected_outputs'][0]['source_link_count'], 2)
        # An alias to controller-owned input is still refused under the remapped
        # candidate boundary, even when a caller expects a compiler artifact.
        q.execution = self.execution()
        with self.assertRaisesRegex(native.Violation, 'linked'):
            native.collect_output(q, alias, self.control / 'refused', compiler_output=True)

    def test_artifact_collection_removes_partial_copy_on_mutation(self):
        q = SimpleNamespace(work=self.roots["candidate"], root=self.roots["checkout"])
        source = q.work / "artifact"
        source.write_bytes(b"actual artifact")
        destination = self.control / "artifact"
        original = os.fstat
        count = 0

        def changed(fd):
            nonlocal count
            count += 1
            result = original(fd)
            if count == 2:
                return SimpleNamespace(st_size=result.st_size + 1,
                    st_mtime_ns=result.st_mtime_ns, st_ctime_ns=result.st_ctime_ns,
                    st_nlink=result.st_nlink)
            return result

        with patch.object(native.os, "fstat", side_effect=changed):
            with self.assertRaisesRegex(native.Violation, "changed"):
                native.collect_output(q, source, destination)
        self.assertFalse(destination.exists())

    def test_fixture_capability_relays_only_to_its_fixed_loopback_peer(self):
        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.sendall(self.request.recv(4096))

        peer = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
        thread = threading.Thread(target=peer.serve_forever, daemon=True)
        thread.start()
        execution = self.execution()
        sockets = tempfile.TemporaryDirectory(
            dir=os.environ.get("BUSBAR_TEST_SOCKET_TMP", os.environ.get("TMPDIR"))
        )
        self.addCleanup(sockets.cleanup)
        execution.fixture_directory = Path(sockets.name)
        fixtures = Fixtures(execution)
        try:
            port = peer.server_address[1]
            fixtures.add(port)
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(5)
                client.connect(str(execution.fixture_directory / (str(port) + ".sock")))
                payload = b"CONNECT 169.254.169.254:80\r\n"
                client.sendall(payload)
                self.assertEqual(client.recv(4096), payload)
            from confinement_entry import start

            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                adapter_port = listener.getsockname()[1]
            adapter = start(
                adapter_port, str(execution.fixture_directory / (str(port) + ".sock"))
            )
            try:
                with socket.create_connection(
                    ("127.0.0.1", adapter_port), timeout=5
                ) as client:
                    client.sendall(b"fixed peer through loopback adapter")
                    self.assertEqual(
                        client.recv(4096), b"fixed peer through loopback adapter"
                    )
            finally:
                adapter.shutdown()
                adapter.server_close()
            self.assertEqual(
                json.loads(execution.fixture_map.read_text()),
                [{"port": port, "socket": str(port) + ".sock"}],
            )
        finally:
            fixtures.close()
            peer.shutdown()
            peer.server_close()
        self.assertEqual(json.loads(execution.fixture_map.read_text()), [])


class SwapCustody(Fixture, unittest.TestCase):
    def invoke(self, swap_limit, observed_swap, kernel_results, *, mount_targets=(), observed_hosts=None):
        execution = self.execution()
        execution.conformance_mounts = [(self.control, Path(target)) for target in mount_targets]
        calls, created = [], []
        memory = self.config['resources']['memory_bytes']
        def client(argv, **kwargs):
            calls.append(argv[0])
            if argv[0] == 'create':
                created.extend(argv)
            payload = ''
            if argv[0] == 'info':
                payload = json.dumps({'SecurityOptions':['name=userns'], 'SwapLimit':swap_limit})
            elif argv[:2] == ['inspect','--format']:
                payload = json.dumps({'Status':'exited','Running':False,'ExitCode':0,'OOMKilled':False})
            elif argv[0] == 'inspect':
                mounts = []
                for index, value in enumerate(created):
                    if value == '--mount':
                        fields = dict(part.split('=',1) if '=' in part else (part,True)
                                      for part in created[index+1].split(','))
                        mounts.append({'Type':fields['type'],'Source':fields['src'],
                            'Destination':fields['dst'],'RW':'readonly' not in fields})
                payload = json.dumps([{'Id':'fixed-container','Image':self.config['image'],
                    'Config':{'User':'1000:1000'},'Mounts':mounts,'HostConfig':{
                        'NetworkMode':'none','ReadonlyRootfs':True,'Privileged':False,'PidMode':'',
                        'IpcMode':'private','CgroupnsMode':'private','Runtime':'runc','CapDrop':['ALL'],
                        'CapAdd':[],'PidsLimit':256,'Memory':memory,'MemorySwap':observed_swap,
                        'NanoCpus':2*10**9,'Devices':[],'DeviceRequests':[],
                        'ExtraHosts': observed_hosts if observed_hosts is not None else
                            [created[i+1] for i,value in enumerate(created) if value == '--add-host'],
                        'ShmSize':64*1024**2,'Tmpfs':{'/tmp':'rw,nosuid,nodev,size=1g,nr_inodes=65536,mode=1777'},
                        'SecurityOpt':['no-new-privileges']}}])
            return subprocess.CompletedProcess(argv,0,stdout=payload,stderr='')
        yielded = False
        error = None
        with patch.object(linux_job_isolation,'prepare_writable',return_value={}), \
                patch.object(linux_job_isolation,'validate_userns',return_value={}), \
                patch.object(linux_job_isolation,'kernel_no_swap',side_effect=kernel_results) as kernel, \
                patch.object(execution,'_client',side_effect=client):
            try:
                with execution.invocation(['python3','-c','pass'],self.roots['checkout'],{}):
                    yielded = True
            except ValueError as failure:
                error = str(failure)
        self.assertIn('--memory-swap='+str(memory),created)
        self.assertIn('--network=none',created)
        self.assertEqual(execution.observations[-1]['fixture_hosts'],
                         [created[i+1] for i,value in enumerate(created) if value == '--add-host'])
        self.assertTrue(execution.observations[-1]['disposed'])
        self.assertEqual(calls[-2:],['rm','container'])
        return yielded,error,execution.observations[-1],kernel.call_count

    def test_a2a_public_dns_fixture_requires_exact_admitted_mount(self):
        for targets, expected in (
            ([], []),
            (['/opt/busbar-conformance/a2a-tools-other'], []),
            (['/opt/busbar-conformance/a2a-tools'],
             ['example.com:104.20.23.154', 'example.com:172.66.147.243']),
            (['/opt/busbar-conformance/oidf', '/opt/busbar-conformance/a2a-tools'],
             ['localhost.emobix.co.uk:127.0.0.1', 'busbar.oidf.test:127.0.0.1',
              'example.com:104.20.23.154', 'example.com:172.66.147.243']),
        ):
            with self.subTest(targets=targets):
                yielded,error,observation,_ = self.invoke(
                    True,self.config['resources']['memory_bytes'],[],mount_targets=targets)
                self.assertTrue(yielded,error)
                self.assertEqual(observation['fixture_hosts'],expected)
                self.assertEqual(observation['network'],'none')

    def test_a2a_dns_fixture_inspection_rejects_missing_or_altered_hosts(self):
        for hosts in ([], ['example.com:127.0.0.1'],
                      ['example.com:104.20.23.154', 'example.com:172.66.147.243',
                       'unexpected.example:127.0.0.1']):
            with self.subTest(hosts=hosts):
                yielded,error,_,_ = self.invoke(
                    True,self.config['resources']['memory_bytes'],[],
                    mount_targets=['/opt/busbar-conformance/a2a-tools'],observed_hosts=hosts)
                self.assertFalse(yielded)
                self.assertIn('runtime weakened candidate isolation',error)

    def test_supported_swap_limit_requires_exact_protected_bound(self):
        yielded,error,observation,calls = self.invoke(True,self.config['resources']['memory_bytes'],[])
        self.assertTrue(yielded)
        self.assertIsNone(error)
        self.assertEqual(calls,0)
        self.assertEqual(observation['swap_bound']['effective_swap_bytes'],0)
        yielded,error,_,calls = self.invoke(True,-1,[])
        self.assertFalse(yielded)
        self.assertIn('MemorySwap',error)
        self.assertEqual(calls,0)

    def test_echoed_swap_request_requires_explicit_support_or_zero_kernel_backing(self):
        memory = self.config['resources']['memory_bytes']
        for flag in (None, 0, 1, 'true'):
            with self.subTest(flag=flag):
                yielded,error,_,calls = self.invoke(flag,memory,[])
                self.assertFalse(yielded)
                self.assertIn('SwapLimit',error)
                self.assertEqual(calls,0)
        yielded,error,_,calls = self.invoke(False,memory,[ValueError('swap is active')])
        self.assertFalse(yielded)
        self.assertIn('swap is active',error)
        self.assertEqual(calls,1)
        proof = {'mechanism':'kernel-zero-swap-capacity','effective_swap_bytes':0}
        yielded,error,observation,calls = self.invoke(False,memory,[dict(proof),dict(proof)])
        self.assertTrue(yielded)
        self.assertIsNone(error)
        self.assertEqual(calls,2)
        self.assertEqual(observation['swap_bound']['mechanism'],'kernel-zero-swap-capacity')

    def test_unsupported_swap_requires_zero_backing_before_start_and_after_disposal(self):
        proof = {'mechanism':'kernel-zero-swap-capacity','effective_swap_bytes':0}
        yielded,error,observation,calls = self.invoke(False,-1,[dict(proof),dict(proof)])
        self.assertTrue(yielded)
        self.assertIsNone(error)
        self.assertEqual(calls,2)
        self.assertEqual(observation['swap_bound']['observed_memory_swap_bytes'],-1)
        self.assertEqual(observation['swap_bound']['after_disposal'],proof)
        yielded,error,_,calls = self.invoke(False,-1,[ValueError('swap became active')])
        self.assertFalse(yielded)
        self.assertIn('swap became active',error)
        self.assertEqual(calls,1)
        yielded,error,observation,calls = self.invoke(False,-1,[dict(proof),ValueError('swap became active')])
        self.assertTrue(yielded)
        self.assertIn('swap became active',error)
        self.assertTrue(observation['disposed'])
        self.assertEqual(calls,2)


@unittest.skipUnless(
    os.environ.get("BUSBAR_CONFINEMENT_TEST_CONFIG"),
    "requires an existing pinned Docker runtime",
)
class ExistingRuntime(Fixture, unittest.TestCase):
    # These three methods are real container witnesses, not mocked tool calls.
    def setUp(self):
        super().setUp()
        self.config = json.loads(
            Path(os.environ["BUSBAR_CONFINEMENT_TEST_CONFIG"]).read_text()
        )

    def test_actual_boundary_denies_host_credentials_writes_and_network(self):
        execution = self.execution()
        (self.control / "secret").write_text("controller secret")
        script = """import json,os,pathlib,socket
r=pathlib.Path(%r)
assert os.getuid()!=0
assert not (r/'control/secret').exists()
assert not pathlib.Path('/var/run/docker.sock').exists()
assert 'CI_JOB_TOKEN' not in os.environ and 'AWS_SECRET_ACCESS_KEY' not in os.environ
assert 'secret-token' not in (r/'checkout/.git/config').read_text()
for p in [r/'harness/created',r/'trusted/created',r/'checkout/created',pathlib.Path('/etc/created')]:
 try:p.write_text('BAD')
 except OSError:pass
 else:raise AssertionError(str(p))
for host in ['169.254.169.254','1.1.1.1']:
 try:socket.create_connection((host,80),timeout=.2)
 except OSError:pass
 else:raise AssertionError(host)
(r/'candidate/output').write_text('actual isolated process')
print(json.dumps({'uid':os.getuid(),'passed':True}))
""" % str(self.base)
        result = execution.run(
            [self.config["python"], "-c", script],
            cwd=self.roots["checkout"],
            env={"CI_JOB_TOKEN": "secret", "AWS_SECRET_ACCESS_KEY": "secret"},
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["passed"])
        self.assertEqual(
            (self.roots["candidate"] / "output").read_text(), "actual isolated process"
        )
        self.assertTrue(execution.observations[-1]["disposed"])
        state = execution.observations[-1]['state_before_disposal']
        self.assertEqual(state['ExitCode'], 0)
        self.assertFalse(state['Running'])

    def test_actual_conformance_manifest_is_readonly_and_rejects_candidate_override(self):
        execution = self.execution()
        execution.set_conformance_capabilities(None, 'GetBusbar/busbar', 'a' * 40)
        script = '''import json,os,pathlib
p=pathlib.Path(os.environ['CONFORMANCE_CAPABILITIES'])
assert json.loads(p.read_text())['toolchain_ready'] is False
try:p.write_text('{}')
except OSError:pass
else:raise AssertionError('candidate rewrote controller capabilities')
'''
        result = execution.run([self.config['python'], '-c', script],
            cwd=self.roots['checkout'], env={'CONFORMANCE_CAPABILITIES': '/forged'},
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(sys.platform == 'linux', 'Unix fixture sockets require a same-kernel Linux controller')
    def test_actual_fixed_fixture_capability_crosses_only_the_unix_socket(self):
        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.sendall(self.request.recv(4096))
        peer = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Echo)
        threading.Thread(target=peer.serve_forever, daemon=True).start()
        execution = self.execution()
        execution.fixture_directory = self.base / 's'
        execution.fixture_directory.mkdir()
        fixtures = Fixtures(execution)
        port = peer.server_address[1]
        try:
            fixtures.add(port)
            script = '''import socket
with socket.create_connection(('127.0.0.1', %d), timeout=5) as peer:
 peer.sendall(b'CONNECT 169.254.169.254:80\\r\\n')
 assert peer.recv(4096) == b'CONNECT 169.254.169.254:80\\r\\n'
try:socket.create_connection(('169.254.169.254',80),timeout=.2)
except OSError:pass
else:raise AssertionError('metadata network available')
''' % port
            result = execution.run([self.config['python'], '-c', script],
                cwd=self.roots['checkout'], env={}, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            fixtures.close()
            peer.shutdown()
            peer.server_close()

    def test_native_candidate_and_controller_dispatch_are_separate(self):
        execution = self.execution()
        q = native.Qualification.__new__(native.Qualification)
        q.execution, q.root, q.work = (
            execution,
            self.roots["checkout"],
            self.roots["candidate"],
        )
        q.evidence = self.control / "evidence"
        q.evidence.mkdir()
        q.env, q.receipt = {}, {"steps": []}
        source = (
            'from pathlib import Path; assert not Path(%r).exists(); print("candidate")'
            % str(q.evidence)
        )
        q.run("candidate", [self.config["python"], "-c", source])
        q.run_controller(
            "controller",
            [
                sys.executable,
                "-c",
                'from pathlib import Path; Path(%r).write_text("controller")'
                % str(q.evidence / "owned"),
            ],
        )
        self.assertEqual((q.evidence / "owned").read_text(), "controller")
        self.assertEqual(
            [r["authority"] for r in q.receipt["steps"]], ["candidate", "controller"]
        )
        self.assertTrue(q.receipt["steps"][0]["container"]["disposed"])

    def test_actual_failure_and_timeout_dispose_the_container(self):
        execution = self.execution()
        result = execution.run(
            [self.config["python"], "-c", "raise SystemExit(7)"],
            cwd=self.roots["checkout"],
            env={},
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 7)
        with self.assertRaises(subprocess.TimeoutExpired):
            execution.run(
                [
                    self.config["python"],
                    "-c",
                    "import os,time; os.fork(); time.sleep(60)",
                ],
                cwd=self.roots["checkout"],
                env={},
                capture_output=True,
                timeout=0.2,
            )
        self.assertTrue(all(row["disposed"] for row in execution.observations))

    def test_actual_missing_pinned_image_fails_without_host_execution(self):
        self.config["image"] = "python@sha256:" + "0" * 64
        execution = self.execution()
        with self.assertRaisesRegex(ValueError, "creation failed"):
            execution.run(
                [self.config["python"], "-c", "raise SystemExit(0)"],
                cwd=self.roots["checkout"],
                env={},
                capture_output=True,
                timeout=30,
            )
        self.assertTrue(execution.observations[-1]["disposed"])


if __name__ == "__main__":
    unittest.main()
