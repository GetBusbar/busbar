# SPDX-License-Identifier: Apache-2.0
"""python3 -I testing/oidf-conformance/test_oidf.py: the OIDF rig finds busbar's OIDC module at the
rev busbar SHIPS (dist/default's lock, held to release/plugin-pins.tsv when that names it)."""
import json
import re
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import oidf  # noqa: E402

CHECKOUT = Path(__file__).resolve().parents[2]
REV = "82b88d5f331a31124cdfccc65fa3d7e9d78fb8ab"
URL = "https://github.com/GetBusbar/busbar-auth-oidc"

LOCK = f'''version = 4

[[package]]
name = "busbar-auth-oidc"
version = "1.6.0"
source = "git+{URL}?rev={REV}#{REV}"

[[package]]
name = "busbar-auth-oidc-plugin"
version = "1.6.0"
source = "git+{URL}?rev={REV}#{REV}"
'''


def checkout(lock=LOCK, pins=None):
    d = Path(tempfile.mkdtemp())
    (d / "dist" / "default").mkdir(parents=True)
    (d / "dist" / "default" / "Cargo.lock").write_text(lock)
    if pins is not None:
        (d / "release").mkdir()
        (d / "release" / "plugin-pins.tsv").write_text(pins)
    return d


class ShippedPin(unittest.TestCase):
    def test_public_source_pin_identities(self):
        for url in ("https://github.com/GetBusbar/busbar-auth-oidc",
                    "https://github.com/GetBusbar/busbar-auth-oidc.git",
                    "https://www.github.com/GetBusbar/busbar-auth-oidc"):
            with self.subTest(url=url):
                self.assertEqual(oidf.oidc_pin(str(checkout(lock=LOCK.replace(URL, url))))["url"], url)

    def test_an_unrecognized_oidc_source_is_refused(self):
        with self.assertRaises(oidf.Refused):
            oidf.oidc_pin(str(checkout(lock=LOCK.replace(URL, "https://example.invalid/GetBusbar/busbar-auth-oidc"))))

    def test_the_oidc_module_is_found_at_the_shipped_pin(self):
        # The real checkout: the rev dist/default's lock pins, which is the rev its manifest names.
        manifest = (CHECKOUT / "dist" / "default" / "Cargo.toml").read_text()
        named = re.search(r'^busbar-auth-oidc-plugin = \{ git = "([^"]+)", rev = "([0-9a-f]{40})" \}',
                          manifest, re.M)
        self.assertIsNotNone(named, "dist/default/Cargo.toml names no busbar-auth-oidc-plugin rev")
        pin = oidf.oidc_pin(str(CHECKOUT))
        self.assertEqual((pin["url"], pin["rev"]), named.groups())
        self.assertRegex(pin["version"], r"^\d+\.\d+\.\d+")

    def test_the_pin_is_read_from_dist_default_not_the_root_lock(self):
        pin = oidf.oidc_pin(str(checkout()))
        self.assertEqual(pin, {"url": URL, "rev": REV, "version": "1.6.0"})

    def test_a_lock_without_the_module_is_refused(self):
        with self.assertRaises(oidf.Refused) as e:
            oidf.oidc_pin(str(checkout(lock="version = 4\n")))
        self.assertIn("dist/default/Cargo.lock pins no busbar-auth-oidc-plugin", str(e.exception))

    def test_plugin_pins_agreeing_with_the_lock_pass(self):
        pins = f"# header\nbusbar-auth-oidc\tv1.6.0\t{REV}\nbusbar-auth-oauth\tv1.6.0\t{'c' * 40}\n"
        self.assertEqual(oidf.oidc_pin(str(checkout(pins=pins)))["rev"], REV)

    def test_plugin_pins_disagreeing_with_the_lock_are_refused(self):
        pins = f"GetBusbar/busbar-auth-oidc\tv1.6.0\t{'d' * 40}\n"
        with self.assertRaises(oidf.Refused) as e:
            oidf.oidc_pin(str(checkout(pins=pins)))
        self.assertIn("release/plugin-pins.tsv", str(e.exception))

    def test_an_empty_plugin_pins_file_defers_to_the_lock(self):
        self.assertEqual(oidf.oidc_pin(str(checkout(pins="# empty until tagged\n")))["rev"], REV)


class Subject(unittest.TestCase):
    def test_contract_overrides_follow_the_exact_manifest_sources(self):
        sources = ("https://github.com/GetBusbar/busbar",
                   "https://github.com/GetBusbar/busbar.git")
        for urls in ((sources[0],), (sources[1],), sources):
            manifest = "\n".join(f'c{i} = {{ package = "busbar-contract", git = "{url}" }}'
                                 for i, url in enumerate(urls))
            args = oidf.contract_patches(manifest, "/checkout/crates/busbar-contract")
            self.assertEqual(set(args[1::2]), {f'patch.{json.dumps(url)}.busbar-contract.path="/checkout/crates/busbar-contract"'
                                             for url in urls})
        with self.assertRaises(oidf.Refused):
            oidf.contract_patches('[patch."https://example.invalid/other"]\nx = { path = "x" }', "/contract")

    def record(self, result, reason=""):
        return {"control": {"ok": True}, "subject": {"modules": [("subject", "FINISHED", result, reason)]},
                "negative": {"modules": [(name, "FINISHED", "FAILED", "expected")
                                         for name in oidf.NEGATIVE_MUST_FAIL]}}

    def test_a_reasonless_skipped_module_is_a_failure(self):
        for info, results in (({"result": "SKIPPED"}, []),
                              ({"result": "SKIPPED", "summary": "  "}, [{"result": "SKIPPED", "src": "label", "msg": ""}]),
                              ({"result": "SKIPPED"}, [{"result": "FAILURE", "msg": "another condition"}])):
            reason = oidf.why(info, results)
            self.assertEqual(reason, "")
            status, armed, text = oidf.decide(self.record("SKIPPED", reason), signoff={})
            self.assertEqual((status, armed), ("fail", True))
            self.assertIn("0/1 pass", text)

    def test_a_suite_supplied_skip_reason_is_preserved(self):
        for info, results, expected in (({"result": "SKIPPED", "summary": "not applicable to plain OAuth"}, [], "not applicable to plain OAuth"),
                                        ({"result": "SKIPPED"}, [{"result": "SKIPPED", "msg": "the suite's condition"}], "the suite's condition")):
            reason = oidf.why(info, results)
            self.assertEqual(reason, expected)
            status, _, text = oidf.decide(self.record("SKIPPED", reason), signoff={})
            self.assertEqual(status, "pass")
            self.assertIn(expected, text)

    def test_skip_handling_does_not_waive_warning_or_unsigned_review(self):
        for result in ("WARNING", "REVIEW"):
            self.assertEqual(oidf.decide(self.record(result, "suite finding"), signoff={})[0], "fail")

    def test_only_the_owner_signed_page_makes_a_review_pass(self):
        record = self.record("REVIEW", "owner must inspect this page")
        record["subject"]["review_pages"] = {"subject": ["a" * 64]}
        self.assertEqual(oidf.decide(record, signoff={"subject": "a" * 64})[0], "pass")
        self.assertEqual(oidf.decide(record, signoff={"subject": "b" * 64})[0], "fail")

    def test_the_subject_is_the_shipped_binary(self):
        # The root workspace's `busbar` is core alone (no transport, so no listener); the binary busbar
        # ships is the distribution's, dist/default.
        argv = oidf.subject_builds("/c")[0]
        self.assertIn("--manifest-path", argv)
        self.assertEqual(argv[argv.index("--manifest-path") + 1], "/c/dist/default/Cargo.toml")
        self.assertEqual(argv[argv.index("--bin") + 1], "busbar")
        self.assertIn("--locked", argv)

    def test_a_subject_that_did_not_boot_is_not_reported_as_unbuilt(self):
        record = {"control": {"ok": True}, "subject_error": "busbar exited during boot (2): x"}
        status, armed, reason = oidf.decide(record, signoff={})
        self.assertEqual((status, armed), ("fail", True))
        self.assertNotIn("could not be built", reason)
        self.assertIn("busbar exited during boot", reason)
        status, _, reason = oidf.decide({"control": {"ok": True}, "build_error": "cargo exited 101"}, signoff={})
        self.assertEqual(status, "fail")
        self.assertIn("the subject could not be built: cargo exited 101", reason)


class InstrumentFailure(unittest.TestCase):
    def test_control_without_a_module_list_is_a_recordable_instrument_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            suite = mock.Mock()
            suite.runner.return_value = (125, "docker runner failed before the official plan started")
            with self.assertRaises(oidf.Refused) as caught:
                oidf.leg_control(suite, directory)
            self.assertTrue(caught.exception.instrument)
            self.assertIn("control runner exited 125", str(caught.exception))
            self.assertIn("runner.log", str(caught.exception))
            self.assertEqual(oidf.decide({"instrument_error": str(caught.exception)})[:2],
                             ("not-run", False))


class FreshStartup(unittest.TestCase):
    def test_generated_config_pins_the_exact_installed_oidc_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ca.pem").write_text("fixture CA")
            archive = root / "oidc.tar.gz"
            archive.write_bytes(b"actual installed fixture archive")
            cfg = oidf.subject_config(fapi2=True, data=1234, admin=1235,
                                      issuer="https://issuer.example", pki=directory,
                                      plugins=directory, jwks_url="https://jwks.example",
                                      clients=[], callback="https://callback.example")
            self.assertEqual(cfg["plugins"]["fetch"], [{
                "url": "https://plugins.example/oidc.tar.gz",
                "sha256": oidf.sha256_file(str(archive)),
            }])
            self.assertEqual(cfg["auth"]["role_bindings"], {oidf.IDP: {oidf.SCOPE: {}}})
            archive.write_bytes(b"a different archive")
            self.assertNotEqual(cfg["plugins"]["fetch"][0]["sha256"], oidf.sha256_file(str(archive)))

    def test_fresh_receipt_binds_actual_inspection_and_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            inspection = {"store_ephemeral": True, "principal_receipt_head_sha256": None,
                          "store_config_sha256": "a" * 64, "requirements": [{"actual": "requirement"}]}
            completed = mock.Mock(returncode=0, stdout=json.dumps(inspection).encode(), stderr=b"")
            with mock.patch.object(oidf.subprocess, "run", return_value=completed) as run:
                argv = oidf.fresh_start("/binary", "/config", "/providers", directory, {})
            self.assertEqual(run.call_args.args[0][-4:],
                             ["--principal-transition", "-", "--transition-action", "inspect"])
            self.assertEqual(argv[-1], "initialize-fresh-and-serve")
            receipt = json.loads(Path(argv[-3]).read_text())
            self.assertEqual(receipt["requirements"], inspection["requirements"])
            self.assertEqual(receipt["store_config_sha256"], inspection["store_config_sha256"])
            self.assertEqual(receipt["creation_evidence_sha256"],
                             oidf.sha256_file(str(Path(directory) / "creation.json")))
            self.assertTrue(receipt["exclusive_instance"])

    def test_retained_store_or_existing_baseline_cannot_be_initialized_fresh(self):
        for state in ({"store_ephemeral": False, "principal_receipt_head_sha256": None},
                      {"store_ephemeral": True, "principal_receipt_head_sha256": "existing"}):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as directory:
                completed = mock.Mock(returncode=0, stdout=json.dumps(state).encode(), stderr=b"")
                with mock.patch.object(oidf.subprocess, "run", return_value=completed):
                    with self.assertRaises(oidf.Refused):
                        oidf.fresh_start("/binary", "/config", "/providers", directory, {})
                self.assertFalse((Path(directory) / "fresh.json").exists())

    def test_failed_boot_cleans_up_process_and_jwks_server(self):
        stub, subject = mock.Mock(port=42), mock.Mock()
        subject.wait.side_effect = oidf.Refused("boot refused")
        with mock.patch.object(oidf, "JwksStub", return_value=stub), \
                mock.patch.object(oidf, "subject_config", return_value={}), \
                mock.patch.object(oidf, "Subject", return_value=subject):
            with self.assertRaises(oidf.Refused):
                oidf.boot("/binary", "/work", "subject", fapi2=True, pki="/pki", plugins="/plugins",
                          jwks={}, clients=[], callback="/callback")
        subject.stop.assert_called_once()
        stub.stop.assert_called_once()

    def test_changed_inputs_do_not_reuse_a_previous_green_run(self):
        with mock.patch.object(oidf, "capture", side_effect=[(0, "a" * 40, ""), (0, "", ""),
                                                           (0, "a" * 40, ""), (0, "changed config", "")]):
            self.assertNotEqual(oidf.run_identity("/checkout"), oidf.run_identity("/checkout"))


if __name__ == "__main__":
    unittest.main()
