# SPDX-License-Identifier: Apache-2.0
"""python3 -I testing/oidf-conformance/test_oidf.py: the OIDF rig finds busbar's OIDC module at the
rev busbar SHIPS (dist/default's lock, held to release/plugin-pins.tsv when that names it)."""
import re
import sys
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
