# SPDX-License-Identifier: Apache-2.0
"""Targeted native OIDF process-adapter checks; no complete suite run. The image stager is release
tooling outside this repository and is tested there."""
import http.server
import json
import os
from pathlib import Path
import sys
import ssl
import stat
import subprocess
import tempfile
import threading
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import oidf



class NativeAdapter(unittest.TestCase):
    def test_native_missing_bundle_never_fetches_or_invokes_docker(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.dict(os.environ, {"CONFORMANCE_CAPABILITIES": "/measured-capabilities",
                                            "MODERNCI_CACHE_DIR": directory}), \
                mock.patch.object(oidf, "NATIVE_BUNDLE", Path(directory) / "missing"), \
                mock.patch.object(oidf.shutil, "which", return_value="/tool"), \
                mock.patch.object(oidf, "suite_source") as source, \
                mock.patch.object(oidf, "compose_command") as compose, \
                mock.patch.object(oidf, "run") as run:
            with self.assertRaisesRegex(oidf.Refused, "native OIDF bundle is unavailable"):
                oidf.run_all(directory)
            source.assert_not_called()
            compose.assert_not_called()
            run.assert_not_called()

    def test_staged_plugin_must_match_distribution_revision(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(oidf, "OIDC_BUNDLE", Path(directory) / "source"):
            oidf.OIDC_BUNDLE.mkdir()
            pin = {"url": "https://github.com/GetBusbar/busbar-auth-oidc", "rev": "a" * 40}
            (oidf.OIDC_BUNDLE / "source-identity.json").write_text(json.dumps(pin))
            (oidf.OIDC_BUNDLE / "Cargo.toml").write_text("[package]\n")
            output = Path(directory) / "output"
            self.assertTrue(oidf.staged_oidc_source(pin, output))
            self.assertEqual((output / "Cargo.toml").read_text(), "[package]\n")
            with self.assertRaisesRegex(oidf.Refused, "revision differs"):
                oidf.staged_oidc_source({**pin, "rev": "b" * 40}, output)

    def test_staged_plugin_build_copy_is_writable_without_changing_measured_inputs(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(oidf, "OIDC_BUNDLE", Path(directory) / "source"):
            source = oidf.OIDC_BUNDLE
            (source / "nested").mkdir(parents=True)
            pin = {"url": "https://github.com/GetBusbar/busbar-auth-oidc", "rev": "a" * 40}
            (source / "source-identity.json").write_text(json.dumps(pin))
            (source / "Cargo.lock").write_text("measured lockfile")
            (source / "nested/tool").write_text("measured executable")
            for path in source.rglob("*"):
                path.chmod(0o555 if path.is_dir() or path.name == "tool" else 0o444)
            source.chmod(0o555)
            original = {path.relative_to(source): (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
                        for path in source.rglob("*") if path.is_file()}
            try:
                output = Path(directory) / "build"
                self.assertTrue(oidf.staged_oidc_source(pin, output))
                self.assertEqual((output / "Cargo.lock").read_text(), "measured lockfile")
                self.assertEqual(stat.S_IMODE((output / "Cargo.lock").stat().st_mode), 0o644)
                self.assertEqual(stat.S_IMODE((output / "nested/tool").stat().st_mode), 0o755)
                self.assertEqual(stat.S_IMODE((output / "nested").stat().st_mode), 0o755)
                (output / "Cargo.lock").write_text("Cargo's updated lockfile")
                (output / "nested/new-source").write_text("build-local file")
                self.assertEqual(original, {
                    path.relative_to(source): (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
                    for path in source.rglob("*") if path.is_file()})
                self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o555)
            finally:
                source.chmod(0o755)
                (source / "nested").chmod(0o755)

    def test_staged_plugin_refuses_a_build_copy_overlapping_measured_source(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(oidf, "OIDC_BUNDLE", Path(directory) / "source"):
            source = oidf.OIDC_BUNDLE
            source.mkdir()
            pin = {"url": "https://github.com/GetBusbar/busbar-auth-oidc", "rev": "a" * 40}
            (source / "source-identity.json").write_text(json.dumps(pin))
            for destination in (source, source / "nested", source.parent):
                with self.subTest(destination=destination), self.assertRaisesRegex(oidf.Refused, "overlap"):
                    oidf.staged_oidc_source(pin, destination)

    def test_java_loader_has_jdk_application_home_and_preserves_pinned_runtime(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(oidf, "NATIVE_BUNDLE", Path(directory) / "bundle"):
            server = oidf.NATIVE_BUNDLE / "server"
            java = server / "opt/java/openjdk"
            (java / "bin").mkdir(parents=True)
            (java / "lib").mkdir()
            (java / "conf").mkdir()
            for name in ("java", "keytool"):
                (java / "bin" / name).write_bytes(b"pinned JDK binary")
            (java / "lib/libjava.so").write_bytes(b"pinned JDK library")
            (server / "lib64").mkdir()
            loader = server / "lib64/ld-linux-x86-64.so.2"
            loader.write_bytes(b"pinned image loader")
            loader.chmod(0o555)
            (server / "runtime.json").write_text(json.dumps({
                "loaders": {"opt/java/openjdk/bin/" + binary: "lib64/ld-linux-x86-64.so.2"
                            for binary in ("java", "keytool")}, "library_dirs": ["opt/java/openjdk/lib"]}))
            suite = oidf.NativeSuite(str(Path(directory) / "work"), "pki", "source", "wheels", "log")
            args = suite.java("keytool", "-importcert", "-keystore", suite.trust)
            private_loader = Path(args[0])
            self.assertNotEqual(private_loader.stat().st_ino, loader.stat().st_ino)
            self.assertEqual(private_loader.read_bytes(), loader.read_bytes())
            self.assertEqual(stat.S_IMODE(loader.stat().st_mode), 0o555)
            self.assertEqual((private_loader.parent.parent / "lib/libjava.so").read_bytes(), b"pinned JDK library")
            self.assertEqual(args[1:], ["--library-path", str(java / "lib"), str(java / "bin/keytool"),
                                       "-importcert", "-keystore", suite.trust])
            self.assertEqual(suite.java("java", "-version")[0], str(private_loader))

    def test_native_runner_preserves_official_plan_and_exports(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(oidf, "native_command", side_effect=lambda *args: list(args)) as command, \
                mock.patch.object(oidf, "run", return_value=0) as run:
            suite = oidf.NativeSuite(directory, "pki", "official-source", "wheels", "rig.log")
            leg = Path(directory) / "subject"
            leg.mkdir()
            (leg / "runner.log").write_text("official output")
            rc, log = suite.runner(str(leg), [oidf.PLAN, "/work/subject/plan-config.json"])
            self.assertEqual((rc, log), (0, "official output"))
            args = command.call_args.args
            self.assertEqual(args[:3], ("python", "usr/local/bin/python3", "scripts/run-test-plan.py"))
            self.assertIn(oidf.PLAN, args)
            self.assertIn(str(leg / "export"), args)
            self.assertIn(str(leg / "plan-config.json"), args)
            self.assertEqual(run.call_args.kwargs["cwd"], "official-source")
            self.assertEqual(run.call_args.kwargs["env"]["CONFORMANCE_SERVER"], oidf.SUITE_BASE)

    def test_changed_wheel_is_refused_before_unpacking(self):
        with tempfile.TemporaryDirectory() as directory:
            url, _ = oidf.WHEELS[0]
            (Path(directory) / url.rsplit("/", 1)[1]).write_bytes(b"tampered")
            with self.assertRaisesRegex(oidf.Refused, "wheel digest differs"):
                oidf.native_wheels(directory, str(Path(directory) / "deps"))
            self.assertFalse((Path(directory) / "deps").exists())


class NativeSuiteTLS(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

        def local_openssl(pki, log, *args):
            subprocess.run(["openssl", *args], cwd=pki, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        self.openssl = local_openssl
        local_openssl(self.root, None, "req", "-x509", "-newkey", "ec", "-pkeyopt",
                      "ec_paramgen_curve:P-256", "-nodes", "-keyout", "ca.key", "-out",
                      "ca.pem", "-days", "1", "-subj", "/CN=fixture CA", "-addext",
                      "basicConstraints=critical,CA:TRUE", "-addext",
                      "keyUsage=critical,keyCertSign,cRLSign")
        with mock.patch.object(oidf, "openssl", side_effect=local_openssl):
            oidf.mint_native_suite_tls(str(self.root), "fixture.log")

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"verified suite")

            def log_message(self, *_args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.root / "suite.pem", self.root / "suite.key")
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def stop():
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        self.addCleanup(stop)
        self.port = server.server_port
        self.suite = oidf.NativeSuite(str(self.root), str(self.root), "source", "wheels", "log")

    def test_request_verifies_fixture_ca_and_hostname(self):
        with mock.patch.object(oidf, "SUITE_BASE", f"https://localhost:{self.port}/"):
            self.assertEqual(self.suite.request("api/runner/available"), b"verified suite")

    def test_request_rejects_wrong_hostname(self):
        with mock.patch.object(oidf, "SUITE_BASE", f"https://127.0.0.1:{self.port}/"):
            with self.assertRaisesRegex(urllib.error.URLError, "CERTIFICATE_VERIFY_FAILED"):
                self.suite.request("api/runner/available")

    def test_request_rejects_untrusted_certificate(self):
        other = self.root / "other"
        other.mkdir()
        self.openssl(other, None, "req", "-x509", "-newkey", "ec", "-pkeyopt",
                     "ec_paramgen_curve:P-256", "-nodes", "-keyout", "ca.key", "-out",
                     "ca.pem", "-days", "1", "-subj", "/CN=unrelated CA", "-addext",
                     "basicConstraints=critical,CA:TRUE")
        self.suite.pki = str(other)
        with mock.patch.object(oidf, "SUITE_BASE", f"https://localhost:{self.port}/"):
            with self.assertRaisesRegex(urllib.error.URLError, "CERTIFICATE_VERIFY_FAILED"):
                self.suite.request("api/runner/available")


if __name__ == "__main__":
    unittest.main()
