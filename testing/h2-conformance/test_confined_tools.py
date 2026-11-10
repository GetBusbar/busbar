"""Tool preflight and mocked image preparation only, never an external suite."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

SOURCE = (Path(__file__).parent / "h2spec.sh").read_text()
START = SOURCE.index('if [ -n "${CONFORMANCE_CAPABILITIES+x}" ]; then')
END = SOURCE.index('\n# h2spec_run ', START)
IMAGE_HELPER = SOURCE[SOURCE.index("ensure_image() {"):SOURCE.index("# ── the instrument:")]
IMAGE_PYTHON = IMAGE_HELPER.split("<<'PYIMAGE'\n", 1)[1].split("\nPYIMAGE", 1)[0]


class ConfinedTools(unittest.TestCase):
    def run_preflight(self, h2_version, caddy_version):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, output in (("h2spec", h2_version), ("caddy", caddy_version)):
                path = root / name
                path.write_text("#!/bin/sh\nprintf '%s\\n' '" + output + "'\n")
                path.chmod(0o700)
            # Forbidden fallback operations fail visibly if the branch regresses.
            for name in ("docker", "curl", "tar"):
                path = root / name
                path.write_text("#!/bin/sh\necho unsafe-fallback >&2\nexit 93\n")
                path.chmod(0o700)
            script = ('set -uo pipefail\nwhy=()\n'
                      'final() { printf "%s\\n" "${why[@]}"; exit 1; }\n'
                      + SOURCE[START:END].replace("/opt/busbar-conformance", str(root))
                      + '\nprintf "%s\\n" "$plat"\n')
            return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                                  env=dict(os.environ, PATH=str(root) + ":" + os.environ["PATH"],
                                           CONFORMANCE_CAPABILITIES="controller-manifest"), timeout=5)

    def test_staged_versions_need_no_docker_or_network(self):
        result = self.run_preflight("Version: 2.6.0 (70ac229)", "v2.11.7 h1:fixture")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "confined\n")
        self.assertNotIn("unsafe-fallback", result.stderr)

    def test_wrong_instrument_or_control_version_is_fatal(self):
        for versions in (("Version: 2.5.0", "v2.11.7"), ("Version: 2.6.0", "v2.11.6")):
            result = self.run_preflight(*versions)
            self.assertEqual(result.returncode, 1)
            self.assertIn("staged", result.stdout)
            self.assertNotIn("unsafe-fallback", result.stderr)


class ImagePreparation(unittest.TestCase):
    def test_cache_hit_never_pulls_and_miss_pulls_only_once(self):
        for cached, pull_exit in ((True, 0), (False, 0), (False, 17)):
            with self.subTest(cached=cached, pull_exit=pull_exit), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                docker = root / "docker"
                docker.write_text('''#!/bin/sh
printf '%s\\n' "$*" >> "$CALLS"
if [ "$1" = image ]; then exit "$INSPECT_EXIT"; fi
if [ "$1" = pull ]; then echo registry-diagnostic; exit "$PULL_EXIT"; fi
exit 99
''')
                docker.chmod(0o700)
                calls, log = root / "calls", root / "pull.log"
                env = dict(os.environ, PATH=str(root) + ":" + os.environ["PATH"],
                           CALLS=str(calls), INSPECT_EXIT="0" if cached else "1",
                           PULL_EXIT=str(pull_exit))
                result = subprocess.run(["bash", "-c", IMAGE_HELPER +
                    '\nensure_image "image@sha256:pin" "$1" --platform linux/amd64',
                    "fixture", str(log)], env=env, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0 if cached else pull_exit, result.stderr)
                observed = calls.read_text().splitlines()
                self.assertEqual(observed[0], "image inspect image@sha256:pin")
                self.assertEqual(len(observed), 1 if cached else 2)
                if not cached:
                    self.assertEqual(observed[1], "pull --quiet --platform linux/amd64 image@sha256:pin")
                    self.assertEqual(log.read_text(), "registry-diagnostic\n")

    def test_pull_timeout_is_retained_without_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "pull.log"
            with mock.patch("sys.argv", ["fixture", "image@sha256:pin", str(log)]), \
                    mock.patch.object(subprocess, "run", side_effect=[
                        subprocess.CompletedProcess([], 1),
                        subprocess.TimeoutExpired(["docker", "pull"], 180)]) as run:
                with self.assertRaises(SystemExit) as stopped:
                    exec(compile(IMAGE_PYTHON, "<image preparation>", "exec"), {})
                self.assertEqual(stopped.exception.code, 124)
                self.assertEqual(run.call_count, 2)
                self.assertEqual(run.call_args.kwargs["timeout"], 180)
                self.assertIn("exceeded 180 seconds", log.read_text())

    def test_container_execution_cannot_pull_implicitly(self):
        invocations = [line for line in SOURCE.splitlines() if "docker run " in line]
        self.assertEqual(len(invocations), 2)
        self.assertTrue(all("docker run --pull=never " in line for line in invocations))


if __name__ == "__main__":
    unittest.main()
