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
        with mock.patch.object(evidence, "target_dir", return_value="/unused/target"), \
                mock.patch.object(evidence, "run", return_value=0) as run:
            evidence.build_subject("unused")
        argv = run.call_args.args[0]
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
                self.assertEqual(pin, {"url": "https://github.com/GetBusbar/busbar-auth-oidc", "rev": "a" * 40})
                root = Path(destination)
                root.mkdir()
                (root / "Cargo.toml").write_text("fixture")
                return True
            with mock.patch.dict(os.environ, CONFORMANCE_CAPABILITIES="manifest"), \
                    mock.patch.object(evidence, "target_dir", return_value=directory), \
                    mock.patch.object(evidence, "oidc_pin", return_value=("1.6.0", "https://github.com/GetBusbar/busbar-auth-oidc", "a" * 40)), \
                    mock.patch.object(evidence.oidf, "staged_oidc_source", side_effect=staged), \
                    mock.patch.object(evidence.oidf, "contract_patches", return_value=[]), \
                    mock.patch.object(evidence, "run", return_value=0) as run:
                evidence.build_subject("unused", oidc=True)
                self.assertEqual(run.call_count, 3)
                for call in run.call_args_list:
                    self.assertEqual(call.args[0][0], "cargo")
                    self.assertEqual(call.kwargs["env"]["CARGO_NET_OFFLINE"], "true")

    def test_absent_or_wrong_pinned_source_fails_before_any_build_or_fetch(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.dict(os.environ, CONFORMANCE_CAPABILITIES="manifest"), \
                mock.patch.object(evidence, "target_dir", return_value=directory), \
                mock.patch.object(evidence, "oidc_pin", return_value=("1.6.0", "https://github.com/GetBusbar/busbar-auth-oidc", "a" * 40)), \
                mock.patch.object(evidence.oidf, "staged_oidc_source", side_effect=evidence.oidf.Refused("staged source mismatch")), \
                mock.patch.object(evidence, "run") as run:
            with self.assertRaisesRegex(evidence.Refused, "staged source mismatch"):
                evidence.build_subject("unused", oidc=True)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
