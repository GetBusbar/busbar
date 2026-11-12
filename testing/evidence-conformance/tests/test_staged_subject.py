"""Confined RBAC source intake and offline build commands; no product builds."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("evidence", Path(__file__).parents[1] / "evidence.py")
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class StagedSubject(unittest.TestCase):
    def test_signature_optimization_is_scoped_to_functional_host_build(self):
        with mock.patch.object(evidence, "cargo_target", return_value="/unused/target"), \
                mock.patch.object(evidence, "run", return_value=0) as run:
            evidence.build_subject("unused")
        argv = run.call_args.args[0]
        self.assertEqual(argv, evidence.oidf.subject_build.busbar_argv(evidence.REPO, "/unused/target"))
        self.assertEqual(argv[:3], ["cargo", "build", "--locked"])
        self.assertEqual(argv[-4:], ["--config", "profile.dev.package.ed25519-dalek.opt-level=3",
                                    "--config", "profile.dev.package.curve25519-dalek.opt-level=3"])
        self.assertNotIn("--release", argv)
        self.assertFalse(any("debug-assertions" in arg or "overflow-checks" in arg for arg in argv))

    def test_rbac_fixtures_enable_bounded_local_telemetry_for_declared_operation(self):
        issuer = mock.Mock(url="https://127.0.0.1:4444/jwks")
        with mock.patch.object(evidence.oidf, "sha256_file", return_value="a" * 64):
            for ceiling in ("full", None):
                cfg = evidence.rbac_config(8000, 8001, "/fixture/plugins", issuer,
                                           "fixture CA", "/fixture/key", {"get_keys"}, ceiling)
                self.assertEqual(cfg["export"], {
                    "rbac-metrics": {"module": "prometheus", "settings": {"buffer_seconds": 60}}})
                provider = cfg["identity-providers"]["rig"]
                self.assertEqual(provider.get("max_admin_scope"), ceiling)
                self.assertEqual(cfg["auth"]["admin_auth"], ["rig"])
        self.assertNotIn("export", evidence.base_config(8000, 8001))

    def test_staged_oidc_uses_offline_builds_without_fetching(self):
        with tempfile.TemporaryDirectory() as directory:
            def staged(pin, destination):
                self.assertEqual((pin["url"], pin["rev"]), ("https://github.com/GetBusbar/busbar-auth-oidc", "a" * 40))
                root = Path(destination)
                self.assertEqual(root, Path(directory) / "oidc-module-src" / ("a" * 12))
                self.assertEqual(list(root.iterdir()), [])
                (root / "Cargo.toml").write_text("fixture")
                return True
            pin = {"url": "https://github.com/GetBusbar/busbar-auth-oidc", "rev": "a" * 40, "version": "1.6.0"}
            with mock.patch.dict(os.environ, CONFORMANCE_CAPABILITIES="manifest"), \
                    mock.patch.object(evidence, "cargo_target", return_value=directory), \
                    mock.patch.object(evidence.oidf, "oidc_pin", return_value=pin), \
                    mock.patch.object(evidence.oidf, "staged_oidc_source", side_effect=staged), \
                    mock.patch.object(evidence.oidf, "contract_patches", return_value=[]), \
                    mock.patch.object(evidence, "run", return_value=0) as run, \
                    mock.patch.object(evidence.oidf, "run", return_value=0) as module_run:
                bins = evidence.build_subject("unused", oidc=True)
                self.assertEqual(run.call_count, 2)
                self.assertEqual(module_run.call_count, 1)
                for call in run.call_args_list + module_run.call_args_list:
                    self.assertEqual(call.args[0][0], "cargo")
                    self.assertEqual(call.kwargs["env"]["CARGO_NET_OFFLINE"], "true")
            self.assertEqual(bins["oidc_version"], "1.6.0")

    def test_absent_or_wrong_pinned_source_fails_before_any_build_or_fetch(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.dict(os.environ, CONFORMANCE_CAPABILITIES="manifest"), \
                mock.patch.object(evidence, "cargo_target", return_value=directory), \
                mock.patch.object(evidence.oidf, "oidc_pin", return_value={"url": "https://github.com/GetBusbar/busbar-auth-oidc", "rev": "a" * 40, "version": "1.6.0"}), \
                mock.patch.object(evidence.oidf, "staged_oidc_source", side_effect=evidence.oidf.Refused("staged source mismatch")), \
                mock.patch.object(evidence, "run") as run, \
                mock.patch.object(evidence.oidf, "run") as module_run:
            with self.assertRaisesRegex(evidence.Refused, "staged source mismatch"):
                evidence.build_subject("unused", oidc=True)
            run.assert_not_called()
            module_run.assert_not_called()

    def test_every_suite_shares_one_build_of_each_subject_artefact(self):
        """tls, h2, oidf-oauth2 and the evidence suites build each artefact with one argv into one
        directory, so only the first suite compiles it (Cargo fingerprints flags, dirs and paths)."""
        sb = evidence.oidf.subject_build
        pin = {"url": "https://github.com/GetBusbar/busbar-auth-oidc", "rev": "b" * 40, "version": "1.6.0"}

        def staged(_pin, destination):
            Path(destination).mkdir(parents=True, exist_ok=True)
            (Path(destination) / "Cargo.toml").write_text("fixture")
            return True

        with tempfile.TemporaryDirectory() as directory:
            target = directory
            oidf_calls, evidence_calls = [], []
            common = (mock.patch.object(evidence.oidf, "oidc_pin", return_value=pin),
                      mock.patch.object(evidence.oidf, "staged_oidc_source", side_effect=staged),
                      mock.patch.object(evidence.oidf, "contract_patches", return_value=["--config", "patch"]))
            with common[0], common[1], common[2], \
                    mock.patch.object(evidence.oidf, "run", side_effect=lambda argv, *a, **k: oidf_calls.append(argv) or 0):
                evidence.oidf.build_subject(evidence.REPO, target, os.path.join(directory, "work"),
                                            os.path.join(directory, "oidf.log"))
            with common[0], common[1], common[2], \
                    mock.patch.object(evidence, "cargo_target", return_value=target), \
                    mock.patch.object(evidence, "run", side_effect=lambda argv, *a, **k: evidence_calls.append(argv) or 0), \
                    mock.patch.object(evidence.oidf, "run", side_effect=lambda argv, *a, **k: evidence_calls.append(argv) or 0):
                evidence.build_subject(os.path.join(directory, "rbac.log"), oidc=True)
                evidence.build_subject(os.path.join(directory, "audit.log"))
        cargo = lambda calls: sorted(map(tuple, (c for c in calls if c[0] == "cargo")))
        # oidf-oauth2 and evidence-rbac: the same three builds; evidence-audit/tls: the busbar build.
        self.assertEqual(cargo(oidf_calls), cargo(evidence_calls[:3]))
        self.assertEqual(evidence_calls[3], sb.busbar_argv(evidence.REPO, target))
        self.assertEqual(len(set(cargo(oidf_calls))), 3)
        # tls.sh and h2spec.sh build through subject_build.py's own CLI: the same busbar argv.
        with mock.patch.dict(os.environ, CARGO_TARGET_DIR=target), \
                mock.patch.object(sb.subprocess, "call", return_value=0) as call, \
                mock.patch("sys.stdout"):
            self.assertEqual(sb.main(["busbar"]), 0)
        self.assertEqual(call.call_args.args[0], sb.busbar_argv(evidence.REPO, target))
        self.assertEqual(call.call_args.kwargs["cwd"], evidence.REPO)
        for script in ("testing/tls-conformance/tls.sh", "testing/h2-conformance/h2spec.sh"):
            text = (Path(evidence.REPO) / script).read_text()
            self.assertIn('python3 -I "$repo/testing/conformance/subject_build.py" busbar', text)
            self.assertNotIn("cargo build", text)


if __name__ == "__main__":
    unittest.main()
