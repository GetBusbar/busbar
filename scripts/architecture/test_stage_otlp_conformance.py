"""Targeted public-image cache, pin, and lifecycle checks; no registry access."""
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import stage_otlp_conformance as stage


class PublicImages(unittest.TestCase):
    def inspect(self, image, architecture="amd64", digest=None):
        return subprocess.CompletedProcess(["docker", "image", "inspect"], 0,
            json.dumps([{"Os": "linux", "Architecture": architecture,
                         "RepoDigests": [digest or image]}]), "")

    def test_exact_cached_platform_never_pulls(self):
        with patch.object(stage.subprocess, "run", return_value=self.inspect(stage.COLLECTOR)) as run:
            self.assertEqual(stage.public_image(stage.COLLECTOR, "amd64"), stage.COLLECTOR)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0][1:3], ["image", "inspect"])
        self.assertIn("linux/amd64", run.call_args.args[0])

    def test_wrong_digest_or_platform_is_not_a_cache_hit(self):
        for result in (self.inspect(stage.COLLECTOR, "arm64"),
                       self.inspect(stage.COLLECTOR, digest="other@sha256:" + "0" * 64)):
            with self.subTest(result=result), patch.object(stage.subprocess, "run", return_value=result):
                self.assertFalse(stage.cached_image(stage.COLLECTOR, "amd64"))

    def test_cached_mirror_never_pulls(self):
        with patch.object(stage, "cached_image", side_effect=[False, True]), \
                patch.object(stage.subprocess, "run") as run:
            self.assertEqual(stage.public_image(stage.COLLECTOR, "amd64"),
                             "mirror.gcr.io/" + stage.COLLECTOR)
        run.assert_not_called()

    def test_hub_miss_fetches_mirror_once_and_verifies(self):
        mirror = "mirror.gcr.io/" + stage.COLLECTOR
        with patch.object(stage, "cached_image", side_effect=[False, False, True]) as inspect, \
                patch.object(stage.subprocess, "run") as run:
            self.assertEqual(stage.public_image(stage.COLLECTOR, "amd64"), mirror)
        run.assert_called_once_with(["docker", "pull", "--platform", "linux/amd64", mirror],
                                    check=True, timeout=300)
        self.assertEqual(inspect.call_args.args, (mirror, "amd64"))

    def test_ghcr_miss_fetches_once_and_bad_identity_fails(self):
        with patch.object(stage, "cached_image", side_effect=[False, False]), \
                patch.object(stage.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "pinned digest and platform"):
                stage.public_image(stage.TELEMETRYGEN, "amd64")
        run.assert_called_once_with(["docker", "pull", "--platform", "linux/amd64", stage.TELEMETRYGEN],
                                    check=True, timeout=300)

    def test_mirror_failure_has_no_hub_fallback_or_retry(self):
        failure = subprocess.CalledProcessError(1, ["docker", "pull"])
        with patch.object(stage, "cached_image", return_value=False), \
                patch.object(stage.subprocess, "run", side_effect=failure) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                stage.public_image(stage.COLLECTOR, "amd64")
        self.assertEqual(run.call_count, 1)
        self.assertTrue(run.call_args.args[0][-1].startswith("mirror.gcr.io/"))

    def test_daemon_failure_does_not_trigger_download(self):
        result = subprocess.CompletedProcess(["docker", "image", "inspect"], 1, "", "daemon unavailable")
        with patch.object(stage.subprocess, "run", return_value=result) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                stage.public_image(stage.COLLECTOR, "amd64")
        self.assertEqual(run.call_count, 1)

    def test_create_failure_is_not_masked_by_removing_absent_container(self):
        failure = subprocess.CalledProcessError(1, ["docker", "create"])
        with patch.object(stage, "public_image", return_value=stage.COLLECTOR), \
                patch.object(stage.subprocess, "run", side_effect=failure) as run:
            with self.assertRaises(subprocess.CalledProcessError) as raised:
                stage.image_binary(stage.COLLECTOR, "amd64", "otelcol-contrib", Path("unused"))
        self.assertIs(raised.exception, failure)
        self.assertEqual(run.call_count, 1)
        self.assertIn("never", run.call_args.args[0])

    def test_copy_failure_cleans_created_container(self):
        failure = subprocess.CalledProcessError(1, ["docker", "cp"])
        with patch.object(stage, "public_image", return_value=stage.COLLECTOR), \
                patch.object(stage.subprocess, "run", side_effect=[None, failure, None]) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                stage.image_binary(stage.COLLECTOR, "amd64", "otelcol-contrib", Path("unused"))
        self.assertEqual([call.args[0][1] for call in run.call_args_list], ["create", "cp", "rm"])


if __name__ == "__main__":
    unittest.main()
