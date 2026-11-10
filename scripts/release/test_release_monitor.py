"""Complete-byte delivery/retention monitor fixtures; signing/log invocation mocked."""

import datetime as dt
import shutil
import unittest
from unittest import mock

import native_provenance as p
import release_monitor as m
import release_verifier as v
import test_release_producer as fixtures


class ReleaseMonitorTests(unittest.TestCase):
    def setUp(self):
        fixture = self.fixture = fixtures.ProducerTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.root = fixture.root
        draft = fixture.prepare()
        fixture.supply_bundles(draft)
        with mock.patch.object(p, "command"):
            result = fixture.finalize(draft)
        (fixture.output / v.BUNDLE).write_bytes(
            p.canonical(fixture.bundle(fixture.output / v.STATEMENT))
        )
        self.catalog = self.root / "catalog.json"
        self.catalog.write_bytes(
            p.canonical(
                {
                    "schema": m.SCHEMA,
                    "valid_until": "2027-12-01T00:00:00Z",
                    "releases": [
                        {
                            "release": "1.6.0",
                            "support_until": "2027-12-01T00:00:00Z",
                            "inventory_sha256": result["inventory_sha256"],
                            "trust": {
                                "path": str(fixture.trust),
                                "sha256": p.digest(fixture.trust),
                            },
                            "files": {
                                path.name: {
                                    "url": "https://release.example/immutable/"
                                    + path.name,
                                    "sha256": p.digest(path),
                                    "size": path.stat().st_size,
                                }
                                for path in fixture.output.iterdir()
                            },
                        }
                    ],
                }
            )
        )
        self.archive = self.root / "archive"
        self.archive.mkdir()
        self.now = dt.datetime(2026, 11, 10, tzinfo=dt.timezone.utc)

    def run_monitor(self):
        def fetch(url, destination, digest, size):
            source = self.fixture.output / destination.name
            self.assertEqual(source.stat().st_size, size)
            self.assertEqual(p.digest(source), digest)
            shutil.copyfile(source, destination)

        with mock.patch.object(m, "fetch", side_effect=fetch), mock.patch.object(
            p, "command"
        ):
            return m.monitor(
                self.catalog, p.digest(self.catalog), self.root, self.archive, self.now
            )

    def test_checks_every_supported_byte_and_preserves_existing_archive(self):
        result = self.run_monitor()
        self.assertEqual(result["status"], "pass")
        self.assertFalse(result["storage_retention_enforced"])
        self.assertFalse(result["log_consistency_observed"])
        self.assertTrue(result["releases"][0]["verified_checkpoint_sha256"])
        self.assertEqual(self.run_monitor(), result)
        retained = next(self.archive.iterdir()) / v.INVENTORY
        retained.chmod(0o600)
        retained.write_bytes(b"mutated")
        with self.assertRaises(ValueError):
            self.run_monitor()

    def test_missing_remote_expired_catalog_and_unpinned_catalog_refuse(self):
        with mock.patch.object(
            m, "fetch", side_effect=OSError("unavailable")
        ), self.assertRaises(OSError):
            m.monitor(self.catalog, p.digest(self.catalog), self.root, now=self.now)
        with self.assertRaises(ValueError):
            m.monitor(self.catalog, "f" * 64, self.root, now=self.now)
        with self.assertRaises(ValueError):
            m.monitor(
                self.catalog,
                p.digest(self.catalog),
                self.root,
                now=dt.datetime(2028, 1, 1, tzinfo=dt.timezone.utc),
            )

    def test_fetch_rejects_credentials_redirects_and_unbounded_downloads(self):
        for url in (
            "http://release.example/file",
            "https://user:secret@release.example/file",
            "https://release.example/file?token=secret",
        ):
            with self.assertRaises(ValueError):
                m.fetch(url, self.root / "bad", "a" * 64, 1)
        with self.assertRaises(ValueError):
            m.NoRedirect().redirect_request(
                None, None, 302, None, None, "https://other.example"
            )
        with self.assertRaises(ValueError):
            m.fetch(
                "https://release.example/file",
                self.root / "bad",
                "a" * 64,
                m.MAX_FILE + 1,
            )


if __name__ == "__main__":
    unittest.main()
