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
